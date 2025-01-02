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
// It finds all the writes in the Application to a pointer allocated
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
// - a return value from f, except if f is a Core api function in whose context the allocation occurs
//   - if the allocation site does not have a context, then we assume it is
//     called from all Core api functions that call the function in which the
//     allocation occurs (to be sound)
//
// - any write to memory (includes globals)
//   - covers writes to parameters, globals, etc.
//   - if we were to allow this, we would have additional proof obligations to satisfy
//
// Thus, an allocation "escapes" a function f if the allocated pointer may alias
// any value that is at an "escape point".
package passthru

import (
	"fmt"
	"go/token"
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
	EscapedAllocs map[AccessedCoreAlloc][]Escape
}

func (a InvalidAccess) String() string {
	return fmt.Sprintf("invalid access in App: %v in %v at %v with %d escaped allocs",
		a.Instruction, a.Instruction.Parent(), a.Pos, len(a.EscapedAllocs))
}

// AccessedCoreAlloc is a pointer allocated in the Core that is accessed
// (read from/written to) in the App.
type AccessedCoreAlloc struct {
	ssa.Value
	Pos   token.Position // Pos is the position at which the alloc occured in the Core
	trace *coreTrace     // trace needs to be a pointer so the type is hashable
}

func (a AccessedCoreAlloc) String() string {
	return fmt.Sprintf("app-accessed alloc in core of %v at %v (trace: %v)",
		a.Value, a.Pos, a.trace)
}

// Escape is a value that results in a AccessedCoreAlloc heap permission
// "escaping" a function.
type Escape struct {
	ssa.Value
	Pos token.Position
}

func (e Escape) String() string {
	return fmt.Sprintf("escape via value %v in %v at %v", e.Value, e.Parent().Name(), e.Pos)
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
	addFuncsAndAllocs(state)

	var res []InvalidAccess
	for _, af := range state.appFuncs {
		if shouldFilterAppAccess(state.spec, af) {
			state.logger.Debugf("Filtering App function according to spec: %v\n", af)
			continue
		}
		unvalidatedCoreAccesses := findCoreAccesses(state, af)
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
	escapes := make(map[AccessedCoreAlloc][]Escape)
	state.logger.Debugf("Validating %v ...\n", acc)
	for _, alloc := range acc.allocs {
		state.logger.Debugf("\talloc: %v\n", alloc)
		for _, coreFunc := range *alloc.trace {
			escs := findEscapes(state, coreFunc, alloc)
			escapes[alloc] = escs
		}
	}

	res := InvalidAccess{
		Instruction:   acc.Instruction,
		Pos:           acc.pos,
		EscapedAllocs: escapes,
	}
	if len(escapes) == 0 {
		return res, false
	}

	return res, true
}

// findEscapes modifies escapes by adding the values whose permissions are a
// subset of alloc's permissions, and "escape" the function f.
//
// This is a purely intra-procedural analysis.
//
//gocyclo:ignore
func findEscapes(state *state, f *ssa.Function, alloc AccessedCoreAlloc) []Escape {
	var res []Escape
	cache := state.cache
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		pos := cache.PtrState.Program.Fset.Position(instr.Pos())
		switch instr := instr.(type) {
		case *ssa.Store, *ssa.MapUpdate, *ssa.Send:
			if write, ok := ptr.PtrWrittenToPtr(instr, pos); ok {
				if hasPermissionsOf(cache, write.Value, alloc) {
					esc := Escape{
						Value: write.Value,
						Pos:   pos,
					}
					res = append(res, esc)
				}
			}
		case *ssa.MakeClosure:
			for _, freeVar := range instr.Bindings {
				if hasPermissionsOf(cache, freeVar, alloc) {
					if !pos.IsValid() {
						pos = cache.PtrState.Program.Fset.Position(freeVar.Pos())
					}
					esc := Escape{
						Value: freeVar,
						Pos:   pos,
					}
					res = append(res, esc)
				}
			}
		case ssa.CallInstruction:
			args := lang.GetArgs(instr)
			for _, arg := range args {
				if hasPermissionsOf(cache, arg, alloc) {
					esc := Escape{
						Value: arg,
						Pos:   pos,
					}
					res = append(res, esc)
				}
			}
		case *ssa.Return:
			for _, r := range instr.Results {
				// skip analyzing if the return is allowed
				if allowedReturn(instr, state.spec) {
					continue
				}

				if hasPermissionsOf(cache, r, alloc) {
					esc := Escape{
						Value: r,
						Pos:   pos,
					}
					res = append(res, esc)
				}
			}
		}
	})

	return res
}

// allowedReturn returns true if ret's parent function is a Core API function.
func allowedReturn(ret *ssa.Return, spec config.DiodonPassThroughSpec) bool {
	for _, cid := range spec.CoreApiFunctions {
		if cid.MatchPackageAndMethod(ret.Parent()) {
			return true
		}
	}

	return false
}

// hasPermissionsOf returns true if the separation logic permissions to access
// all (shallow) objects in val also give permission to access all (shallow)
// objects allocated in alloc.
//
// In Gobra, separation logic permissions are "shallow", so we get the abstract
// address (pointer analysis node id) of each object in the value or
// allocation's points-to-set.
// This ensures that we get the heap addresses of any allocated struct fields,
// array/slice elements, etc within alloc, but not the underlying data which
// the pointers point to.
func hasPermissionsOf(cache *ptr.AliasCache, val ssa.Value, alloc AccessedCoreAlloc) bool {
	if val.Parent() == nil {
		return false
	}

	valObjs := cache.Objects(val)
	allocObjs := cache.Objects(alloc.Value)
	for valObj := range valObjs {
		for allocObj := range allocObjs {
			if valObj.NodeID() != allocObj.NodeID() {
				return false
			}
		}
	}

	return true
}

type state struct {
	logger       *config.LogGroup
	spec         config.DiodonPassThroughSpec
	cache        *ptr.AliasCache
	appFuncs     []*ssa.Function
	coreAllocIds *intsets.Sparse
	// a single node id can refer to values allocated in multiple calling contexts
	id2allocs map[pointer.NodeID][]allocInCore
}

func newState(s *ptr.State, cache *ptr.AliasCache, spec config.DiodonPassThroughSpec) *state {
	return &state{
		logger:       s.Logger,
		spec:         spec,
		cache:        cache,
		appFuncs:     nil,
		coreAllocIds: &intsets.Sparse{},
		id2allocs:    make(map[pointer.NodeID][]allocInCore),
	}
}

// allocInCore is a value allocated in the Core.
//
// The allocation can occur in multiple different calling contexts which is why
// there can be more than one trace.
type allocInCore struct {
	ssa.Value
	trace *coreTrace
}

func (ac allocInCore) String() string {
	return fmt.Sprintf("alloc in core: %v (trace: %v)", ac.Value, ac.trace)
}

// addAllocsInCore adds values allocated in the core with trace tr to state.
func addAllocsInCore(state *state, coreFunc *ssa.Function, tr coreTrace) {
	if shouldFilterCoreAlloc(state.spec, coreFunc) {
		state.logger.Debugf("Filtering Core function according to spec: %v\n", coreFunc)
		return
	}

	if len(tr) == 0 {
		panic(fmt.Errorf("core func has empty trace: %v", coreFunc))
	}

	lang.IterateInstructions(coreFunc, func(_ int, instr ssa.Instruction) {
		if !instr.Pos().IsValid() {
			return
		}

		if alloc, ok := instr.(*ssa.Alloc); ok {
			// alloc can only escape a function if it is on the heap
			if !alloc.Heap {
				return
			}
		}

		switch instr.(type) {
		case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
			val := instr.(ssa.Value) // safe conversion
			objs := state.cache.Objects(val)
			alloc := allocInCore{
				Value: val,
				trace: &tr,
			}
			for obj := range objs {
				state.coreAllocIds.Insert(int(obj.NodeID()))
				state.logger.Debugf("At node id %v in %v adding %v", obj.NodeID(), val.Parent().String(), alloc)
				state.id2allocs[obj.NodeID()] = append(state.id2allocs[obj.NodeID()], alloc)
			}
		}
	})
}

// coreTrace is the Core function trace from a Core API function to the function
// that allocates a CoreAlloc.
//
// This is also the list of functions the CoreAlloc must not "escape" from.
type coreTrace []*ssa.Function

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
	return fmt.Sprintf("(unvalidated) core access: %v in %v at %v of allocs: %v",
		ua.Instruction, ua.Instruction.Parent(), ua.pos, ua.allocs)
}

func findCoreAccesses(state *state, appFunc *ssa.Function) []unvalidatedCoreAccess {
	var res []unvalidatedCoreAccess
	lang.IterateInstructions(appFunc, func(_ int, instr ssa.Instruction) {
		if !instr.Pos().IsValid() {
			return
		}

		prog := state.cache.PtrState.Program
		pos := prog.Fset.Position(instr.Pos())
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
							Pos:   prog.Fset.Position(aic.Value.Pos()),
							trace: aic.trace,
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

// addFuncsAndAllocs adds Core and App functions to state as well as Core
// allocations.
//
// A function is in the App if it is reachable from the main function
// (callgraph root) and not from any Core function.
// A function is in the Core if it is reachable from any Core function.
func addFuncsAndAllocs(state *state) {
	// elt is a node in the callgraph.
	type elt struct {
		*callgraph.Node
		context context // context is the context of the node
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
	root := eltctx{elt: elt{Node: cg.Root, context: app}, coreTrace: nil, indent: 0}
	stack := []eltctx{root}
	seen := map[elt]bool{}
	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		if seen[cur.elt] {
			continue
		}

		if state.logger.LogsTrace() {
			state.logger.Tracef(
				"%s(%s) %v: (core trace: %v)\n",
				strings.Repeat("  ", cur.indent),
				cur.context.String(),
				cur.Func.String(),
				cur.coreTrace)
		}

		switch cur.context {
		case core:
			addAllocsInCore(state, cur.Func, cur.coreTrace)
		case app:
			state.appFuncs = append(state.appFuncs, cur.Func)
		default:
			panic(fmt.Errorf("invalid context for callgraph node %v: %v", cur.Node, cur.context))
		}

		seen[elt{Node: cur.Node, context: cur.context}] = true

		for _, edge := range cur.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}

			nextCtx := cur.context
			// only change the context if it's not in the core
			if nextCtx != core {
				nextCtx = contextOf(state.spec, edge.Callee.Func)
			}
			nextTrace := cur.coreTrace
			if nextCtx == core {
				nextTrace = append(cur.coreTrace, edge.Callee.Func)
			}

			stack = append(stack, eltctx{
				elt:       elt{Node: edge.Callee, context: nextCtx},
				coreTrace: nextTrace,
				indent:    cur.indent + 1,
			})
		}
	}
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
	for _, apiFuncId := range spec.CoreApiFunctions {
		for f := range coreFuncs {
			if apiFuncId.MatchPackageAndMethod(f) {
				funcs[f] = true
				break
			}
		}
	}

	if len(funcs) != len(spec.CoreApiFunctions) {
		return funcs, fmt.Errorf("missing some core api functions: want %v, got %v", spec.CoreApiFunctions, funcs)
	}

	return funcs, nil
}

func returnNodes(f *ssa.Function) []*ssa.Return {
	var rets []*ssa.Return
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		if ret, ok := instr.(*ssa.Return); ok {
			rets = append(rets, ret)
		}
	})

	return rets
}

// appWrite is a write to a pointer allocated in the app.
type appWrite struct {
	ptr.Write
	id pointer.NodeID
}

type context uint

const (
	core = iota
	app
)

func (c context) String() string {
	switch c {
	case core:
		return "Core"
	case app:
		return "App"
	default:
		panic("invalid context")
	}
}

func isCoreApiFunc(spec config.DiodonPassThroughSpec, f *ssa.Function) bool {
	for _, coreApiFuncId := range spec.CoreApiFunctions {
		if coreApiFuncId.MatchPackageAndMethod(f) {
			return true
		}
	}

	return false
}

func contextOf(spec config.DiodonPassThroughSpec, f *ssa.Function) context {
	if isCoreApiFunc(spec, f) {
		return core
	}

	return app
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
		for alloc, escapes := range acc.EscapedAllocs {
			report.WriteString(fmt.Sprintf("\t\t%v\n", alloc))
			for _, escape := range escapes {
				report.WriteString(fmt.Sprintf("\t\t\t%v\n", escape))
			}
		}
	}

	return report.String(), failed
}
