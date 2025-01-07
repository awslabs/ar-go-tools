// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package passthru implements the Diodon-specific pass-through analysis.
// It finds all the accesses in the Application to a pointer allocated
// in the Core without correct separation logic permissions.
//
// We cannot prove that an allocation in the Core must alias a return value
// because the pointer analysis overapproximates.
// Therefore, we prove that an allocation in the Core must alias a return value if
// it must not alias any value that "escapes" the Core api function in which it
// is allocated through any other means.
// We define an "escape point" of a function f in the Core as:
// - an argument or free variable to any function call or closure in f
//   - if this is the case, we start an inter-procedural analysis
//
// - any write to memory (includes globals)
//   - covers writes to parameters, globals, etc.
//   - if we were to allow this, we would have additional proof obligations to satisfy:
//     we can't temporarily store something on the heap because the pointer analysis doesn't
//     know the lifetime of the allocation
//
// Thus, an allocation "escapes" a function f if the allocated pointer may alias
// any value that is at an "escape point".
package passthru

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/container/intsets"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// AnalysisResult is the result of the analysis.
type AnalysisResult struct {
	// InvalidAccesses is all the reads/writes in the Application to a pointer
	// allocated in the Core without correct separation logic permissions.
	InvalidAccesses []InvalidAccess
}

// InvalidAccess is an instruction in the App that accesses a pointer
// allocated in the Core without separation logic permissions.
type InvalidAccess struct {
	ssa.Instruction
	Pos           token.Position
	EscapedAllocs []EscapedCoreAlloc
}

func (a InvalidAccess) String() string {
	return fmt.Sprintf("invalid access in App: %v in %v at %v with %d escaped allocs",
		a.Instruction, a.Instruction.Parent(), a.Pos, len(a.EscapedAllocs))
}

// AccessedCoreAlloc is a pointer allocated in the Core that is accessed
// (read from/written to) in the App.
//
// It must also possibly alias any parameter or return value of a Core API
// function configured in the spec.
type AccessedCoreAlloc struct {
	ssa.Value
	Pos   token.Position // Pos is the position at which the alloc occured in the Core
	trace coreTrace
}

func (a AccessedCoreAlloc) String() string {
	return fmt.Sprintf("app-accessed alloc in core of %v at %v (trace: %v)",
		a.Value, a.Pos, a.trace)
}

// Analyze runs the analysis on all pass through problems specified in the
// config.
func Analyze(s *ptr.State) (AnalysisResult, error) {
	var res []InvalidAccess
	cache := ptr.NewAliasCache(s)

	for _, spec := range s.Config.DiodonPassThroughProblems {
		state := newState(s, cache, spec)
		invalidAccesses := analyze(state)
		res = append(res, invalidAccesses...)
	}

	return AnalysisResult{InvalidAccesses: res}, nil
}

func analyze(state *state) []InvalidAccess {
	funcs := categorizeFuncs(state)
	state.funcs = funcs
	retIds := returnParamIdsWithPermission(state, state.funcs.app)

	for _, coreFunc := range state.funcs.core {
		addAllocsInCore(state, retIds, coreFunc)
	}

	if state.coreAllocIds.Len() == 0 {
		state.logger.Infof("No allocations in the Core found that may leak permissions to a Core API return value")
	}

	var res []InvalidAccess
	for _, appFunc := range state.funcs.app {
		if shouldFilterAppAccess(state.spec, appFunc) {
			state.logger.Debugf("Filtering App function according to spec: %v\n", appFunc)
			continue
		}
		unvalidatedCoreAccesses := findCoreAccesses(state, appFunc)
		for _, unvalidatedAcc := range unvalidatedCoreAccesses {
			if acc, ok := isInvalidCoreAccess(state, unvalidatedAcc); ok {
				state.logger.Infof("Found %v\n", acc)
				res = append(res, acc)
			}
		}
	}

	return res
}

// isInvalidCoreAccess returns the access and true if acc reads or writes from a
// heap location allocated in the Core that does not pass through the proper
// return values.
func isInvalidCoreAccess(state *state, acc unvalidatedCoreAccess) (InvalidAccess, bool) {
	var escapedAllocs []EscapedCoreAlloc
	state.logger.Debugf("Validating %v ...\n", acc)
	for _, alloc := range acc.allocs {
		state.logger.Debugf("\talloc: %v\n", alloc)
		var escapes []Escape
		// Find escapes for every Core function in the alloc's trace
		// on the transition from a core func to unknown (stdlib etc), run escape analysis
		for _, coreFunc := range alloc.trace {
			if funcDoesNotLeakArgs(coreFunc.f) {
				state.logger.Debugf(
					"\t\tskipping escape check because Core function does not leak args: %v\n",
					coreFunc)
				continue
			}

			escs := findEscapes(state, coreFunc.f, alloc)
			state.logger.Debugf("\t\t%v escapes: %v\n", coreFunc, escapes)
			escapes = append(escapes, escs...)
		}

		// Alloc is valid if it does not escape
		if len(escapes) == 0 {
			continue
		}

		esc := EscapedCoreAlloc{
			AccessedCoreAlloc: alloc,
			Escapes:           escapes,
		}
		escapedAllocs = append(escapedAllocs, esc)
	}

	res := InvalidAccess{
		Instruction:   acc.Instruction,
		Pos:           acc.pos,
		EscapedAllocs: escapedAllocs,
	}
	if len(escapedAllocs) == 0 {
		return res, false
	}

	return res, true
}

// returnParamIdsWithPermission returns a set of node ids that require
// separation logic permissions according to state.spec.
func returnParamIdsWithPermission(state *state, appFuncs []*ssa.Function) *intsets.Sparse {
	var vals []ssa.Value
	for _, f := range appFuncs {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				return
			}

			callee := call.Common().StaticCallee()
			if callee == nil {
				return
			}

			funcId, ok := isCoreApiFunc(state.spec, callee)
			if !ok {
				return
			}

			// If the call returns a tuple, add the respective return value
			// extract instructions to vals, otherwise add the result of the
			// call
			isTupleReturn := callee.Signature.Results().Len() > 1
			if isTupleReturn {
				if call.Value().Referrers() == nil {
					panic(fmt.Errorf(
						"no referrers for Core API function call with multiple returns: %v (signature: %v)",
						instr, callee.Signature))
				}

				for _, refInstr := range *call.Value().Referrers() {
					extract, ok := refInstr.(*ssa.Extract)
					if !ok {
						continue
					}
					for _, retIdx := range funcId.ReturnIndices {
						if extract.Index == retIdx {
							vals = append(vals, extract)
						}
					}
				}
			} else {
				vals = append(vals, call.Value())
			}
		})
	}

	res := &intsets.Sparse{}
	for _, val := range vals {
		objs := state.cache.Objects(val)
		for obj := range objs {
			res.Insert(int(obj.NodeID()))
		}
	}

	return res
}

type state struct {
	logger       *config.LogGroup
	spec         config.DiodonPassThroughSpec
	cache        *ptr.AliasCache
	funcs        funcs
	coreAllocIds *intsets.Sparse
	// a single node id can refer to values allocated in multiple calling contexts
	id2allocs map[pointer.NodeID][]allocInCore

	fset *token.FileSet
}

func newState(s *ptr.State, cache *ptr.AliasCache, spec config.DiodonPassThroughSpec) *state {
	return &state{
		logger:       s.Logger,
		spec:         spec,
		cache:        cache,
		funcs:        funcs{core: nil, app: nil},
		coreAllocIds: &intsets.Sparse{},
		id2allocs:    make(map[pointer.NodeID][]allocInCore),
		fset:         cache.PtrState.Program.Fset,
	}
}

// allocInCore is a value allocated in a function reachable from a Core API
// function.
//
// The allocation can occur in multiple different calling contexts which is why
// there can be more than one allocInCore for a given SSA value.
type allocInCore struct {
	ssa.Value
	trace *coreTrace
}

func (ac allocInCore) String() string {
	return fmt.Sprintf("alloc in core: %v (trace: %v)", ac.Value, ac.trace)
}

// addAllocsInCore adds values allocated in the Core with trace tr to state.
// The values must possibly alias any specified Core API function's return
// value.
func addAllocsInCore(state *state, retIds *intsets.Sparse, coreFunc coreFuncWithTrace) {
	tr := coreFunc.trace
	if len(tr) == 0 {
		panic(fmt.Errorf("core func has empty trace: %v", coreFunc))
	}

	lang.IterateInstructions(coreFunc.f, func(_ int, instr ssa.Instruction) {
		if !instr.Pos().IsValid() {
			return
		}

		if alloc, ok := instr.(*ssa.Alloc); ok {
			// alloc can only escape a function if it is on the heap
			if !alloc.Heap {
				return
			}

			// We assume that errors are only used as scalar values
			if alloc.Type() == nil || isAllocatedErrorType(alloc.Type()) {
				return
			}
		}

		if val, ok := isAllocInstr(instr); ok {
			alloc := allocInCore{
				Value: val,
				trace: &tr,
			}
			objs := state.cache.Objects(val)
			for obj := range objs {
				// obj must may-alias a return value
				if !retIds.Has(int(obj.NodeID())) {
					continue
				}

				state.logger.Debugf("At node id %v in %v adding %v at %v\n",
					obj.NodeID(), val.Parent().String(), alloc, state.fset.Position(alloc.Pos()))
				state.coreAllocIds.Insert(int(obj.NodeID()))
				state.id2allocs[obj.NodeID()] = append(state.id2allocs[obj.NodeID()], alloc)
			}
		}
	})
}

func isAllocInstr(instr ssa.Instruction) (ssa.Value, bool) {
	switch instr.(type) {
	case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice, *ssa.MakeClosure:
		return instr.(ssa.Value), true // safe conversion
	default:
		return nil, false
	}
}

// coreTrace is the Core function trace from a Core API function to the function
// that allocates a CoreAlloc.
//
// This is also the list of functions the CoreAlloc must not "escape" from.
type coreTrace []coreFunc

func (t coreTrace) String() string {
	if len(t) == 0 {
		return "<empty>"
	}

	var s []string
	for _, f := range t {
		s = append(s, f.String())
	}

	return strings.Join(s, "->")
}

// unvalidatedCoreAccess is an instruction in the App that accesses (reads from
// or writes to) a pointer allocated in the core.
// This instruction's separation logic permissions have not yet been validated
// which is why it's a distinct type.
type unvalidatedCoreAccess struct {
	ssa.Instruction
	pos    token.Position
	allocs []AccessedCoreAlloc
}

func (ua unvalidatedCoreAccess) String() string {
	return fmt.Sprintf("(unvalidated) core access: %v in %v at %v of %d allocs",
		ua.Instruction, ua.Instruction.Parent(), ua.pos, len(ua.allocs))
}

func findCoreAccesses(state *state, appFunc *ssa.Function) []unvalidatedCoreAccess {
	var res []unvalidatedCoreAccess
	lang.IterateInstructions(appFunc, func(_ int, instr ssa.Instruction) {
		if !instr.Pos().IsValid() {
			return
		}

		pos := state.fset.Position(instr.Pos())
		var accessedVals []ssa.Value
		if write, ok := ptr.PtrWrittenToPtr(instr, pos); ok {
			accessedVals = append(accessedVals, write.Target)
		} else if write, ok := ptr.PtrWrittenTo(instr, pos); ok {
			accessedVals = append(accessedVals, write.Target)
		} else if read, ok := ptr.PtrsReadFrom(instr, pos); ok {
			for _, val := range read.Values {
				accessedVals = append(accessedVals, val)
			}
		}

		var allocs []AccessedCoreAlloc
		seenAllocs := make(map[allocInCore]struct{})
		for _, accessedVal := range accessedVals {
			objs := state.cache.Objects(accessedVal)
			for obj := range objs {
				if state.coreAllocIds.Has(int(obj.NodeID())) {
					aics, ok := state.id2allocs[obj.NodeID()]
					if !ok {
						panic(fmt.Errorf(
							"failed to find allocs in core for access %v at %v to node id: %v",
							instr, pos, obj.NodeID()))
					}
					for _, aic := range aics {
						if _, ok := seenAllocs[aic]; ok {
							continue
						}
						seenAllocs[aic] = struct{}{}
						alloc := AccessedCoreAlloc{
							Value: aic.Value,
							Pos:   state.fset.Position(aic.Value.Pos()),
							trace: *aic.trace,
						}
						allocs = append(allocs, alloc)
					}
				}
			}
		}
		if len(allocs) > 0 {
			acc := unvalidatedCoreAccess{Instruction: instr, pos: pos, allocs: allocs}
			res = append(res, acc)
		}
	})

	return res
}

type funcs struct {
	core []coreFuncWithTrace
	app  []*ssa.Function
}

type coreFunc struct {
	f   *ssa.Function
	ctx funcContext
}

func (cf coreFunc) String() string {
	return fmt.Sprintf("%s (in %s)", cf.f.String(), cf.ctx.String())
}

type coreFuncWithTrace struct {
	coreFunc
	trace coreTrace
}

func (cf coreFuncWithTrace) String() string {
	return fmt.Sprintf("%s trace: %s", cf.String(), cf.trace.String())
}

// categorizeFuncs returns the Core and App functions.
//
// A function is in the App if it is reachable from the main function
// (callgraph root) and not from any Core function.
// A function is in the Core if it is reachable from any Core function.
func categorizeFuncs(state *state) funcs {
	var coreFuncs []coreFuncWithTrace
	var appFuncs []*ssa.Function

	// elt is a node in the callgraph.
	type elt struct {
		*callgraph.Node
		context funcContext
		trace   *[]*ssa.Function
	}

	// eltctx is an elt with more context.
	type eltctx struct {
		elt
		coreTrace coreTrace
		indent    int // indent is only used for debugging
	}

	// Traverse callgraph with DFS because once a function is called in a Core context,
	// all of its transitive callees are in the Core context as well.
	cg := state.cache.PtrState.PointerAnalysis.CallGraph
	root := eltctx{
		elt:       elt{Node: cg.Root, context: app, trace: &[]*ssa.Function{}},
		coreTrace: nil,
		indent:    0,
	}
	stack := []eltctx{root}
	seen := map[elt]bool{}
	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		if seen[cur.elt] {
			continue
		}

		switch cur.context {
		case unknown:
			if len(cur.coreTrace) > 0 {
				cf := coreFuncWithTrace{
					coreFunc{
						cur.Func,
						cur.context,
					},
					cur.coreTrace,
				}
				coreFuncs = append(coreFuncs, cf)
			} else {
				appFuncs = append(appFuncs, cur.Func)
			}
		case core:
			// add the current function to the trace
			cf := coreFunc{
				f:   cur.Func,
				ctx: cur.context,
			}
			cur.coreTrace = append(cur.coreTrace, cf)
			cft := coreFuncWithTrace{
				cf,
				cur.coreTrace,
			}
			coreFuncs = append(coreFuncs, cft)
		case app:
			if len(cur.coreTrace) > 0 {
				// App function called in Core gets Core context
				// add the current function to the trace
				cf := coreFunc{
					f:   cur.Func,
					ctx: app,
				}
				cur.coreTrace = append(cur.coreTrace, cf)
				cft := coreFuncWithTrace{
					cf,
					cur.coreTrace,
				}
				coreFuncs = append(coreFuncs, cft)
			} else {
				appFuncs = append(appFuncs, cur.Func)
			}
		default:
			panic(fmt.Errorf("invalid context for callgraph node %v: %v", cur.Node, cur.context))
		}

		if state.logger.LogsTrace() {
			state.logger.Tracef(
				"%s(%s) %v: (core trace: %v)\n",
				strings.Repeat("  ", cur.indent),
				cur.context.String(),
				cur.Func.String(),
				cur.coreTrace)
		}

		seen[cur.elt] = true

		for _, edge := range cur.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}

			nextCtx := contextOf(state.spec, edge.Callee.Func)
			stack = append(stack, eltctx{
				elt: elt{
					Node:    edge.Callee,
					context: nextCtx,
				},
				coreTrace: cur.coreTrace,
				indent:    cur.indent + 1,
			})
		}
	}

	// Remove any functions in the App that are also in the Core
	// appFuncs = slices.DeleteFunc(appFuncs, func(appFunc *ssa.Function) bool {
	// 	for _, coreFunc := range coreFuncs {
	// 		if coreFunc.f == appFunc {
	// 			return true
	// 		}
	// 	}

	// 	return false
	// })

	return funcs{core: coreFuncs, app: appFuncs}
}

func isFalsePositive(spec config.DiodonPassThroughSpec, alloc AccessedCoreAlloc) bool {
	for _, filterId := range spec.AppAccessFilters {
		if filterId.MatchPackageAndMethod(alloc.Parent()) {
			return true
		}
	}

	return false
}

func coreApiFuncs(spec config.DiodonPassThroughSpec, coreFuncs map[*ssa.Function]bool) (map[*ssa.Function]bool, error) {
	funcs := make(map[*ssa.Function]bool)
	for _, apiFuncId := range spec.CoreApiFunctionReturnedValues {
		for f := range coreFuncs {
			if apiFuncId.MatchPackageAndMethod(f) {
				funcs[f] = true
				break
			}
		}
	}

	if len(funcs) != len(spec.CoreApiFunctionReturnedValues) {
		return funcs, fmt.Errorf("missing some core api functions: want %v, got %v", spec.CoreApiFunctionReturnedValues, funcs)
	}

	return funcs, nil
}

type funcContext uint

const (
	core = iota
	app
	unknown
)

func (c funcContext) String() string {
	switch c {
	case core:
		return "Core"
	case app:
		return "App"
	case unknown:
		return "Unknown"
	default:
		panic("invalid context")
	}
}

func isCoreApiFunc(spec config.DiodonPassThroughSpec, f *ssa.Function) (config.CodeIdentifier, bool) {
	for _, funcId := range spec.CoreApiFunctionReturnedValues {
		if funcId.MatchPackageAndMethod(f) {
			return funcId, true
		}
	}

	return config.CodeIdentifier{}, false
}

func isCoreFunc(spec config.DiodonPassThroughSpec, f *ssa.Function) bool {
	for _, funcId := range spec.CoreFunctions {
		if funcId.MatchPackageAndMethod(f) {
			return true
		}
	}

	_, ok := isCoreApiFunc(spec, f)
	return ok
}

func isAppFunc(spec config.DiodonPassThroughSpec, f *ssa.Function) bool {
	for _, funcId := range spec.AppFunctions {
		if funcId.MatchPackageAndMethod(f) {
			return true
		}
	}

	return false
}

func contextOf(spec config.DiodonPassThroughSpec, f *ssa.Function) funcContext {
	if isCoreFunc(spec, f) {
		return core
	} else if isAppFunc(spec, f) {
		return app
	} else {
		return unknown
	}
}

func shouldFilterAppAccess(spec config.DiodonPassThroughSpec, f *ssa.Function) bool {
	for _, cid := range spec.AppAccessFilters {
		if cid.MatchPackageAndMethod(f) {
			return true
		}
	}

	return false
}

func shouldFilterCoreAlloc(spec config.DiodonPassThroughSpec, f *ssa.Function) bool {
	for _, cid := range spec.CoreAllocFilters {
		if cid.MatchPackageAndMethod(f) {
			return true
		}
	}

	return false
}

func isAllocatedErrorType(t types.Type) bool {
	typ := t
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem().Underlying()
	}

	return types.AssignableTo(typ, types.Universe.Lookup("error").Type())
}

// ReportResults returns res as a formatted string and true if the analysis failed.
func ReportResults(res AnalysisResult) (string, bool) {
	failed := false
	report := &strings.Builder{}
	if len(res.InvalidAccesses) > 0 {
		report.WriteString(formatutil.Red(
			"Found accesses to pointers allocated in the Core without permission:\n"))
		failed = true
	} else {
		report.WriteString(formatutil.Green("All core allocation permissions are valid\n"))
	}
	for _, acc := range res.InvalidAccesses {
		report.WriteString(fmt.Sprintf("\t%v\n", acc))
		for _, alloc := range acc.EscapedAllocs {
			report.WriteString(fmt.Sprintf("\t\t%v\n", alloc.AccessedCoreAlloc))
			for _, escape := range alloc.Escapes {
				report.WriteString(fmt.Sprintf("\t\t\t%v\n", escape))
			}
		}
	}

	return report.String(), failed
}
