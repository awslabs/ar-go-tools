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
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/exp/maps"
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
	Vals          []accessedVal
	Pos           token.Position
	trace         funcTrace
	EscapedAllocs []EscapedCoreAlloc
}

func (a InvalidAccess) String() string {
	var vals []string
	for _, val := range a.Vals {
		vals = append(vals, fmt.Sprintf("%v (type %v)", val.String(), val.Type().String()))
	}
	parent := a.Vals[0].Parent()

	return fmt.Sprintf("invalid access in App via %v in %v at %v with %d escaped allocs (trace: %v)",
		strings.Join(vals, ", "), parent, a.Pos, len(a.EscapedAllocs), a.trace)
}

// AccessedCoreAlloc is a pointer allocated in the Core that is accessed
// (read from/written to) in the App.
//
// It must may-alias an allocation in the Core package.
type AccessedCoreAlloc struct {
	ssa.Value
	Pos    token.Position // Pos is the position at which the alloc occured in the Core
	trace  coreTrace
	nodeId pointer.NodeID // nodeId is the pointer node id for the value
}

func (a AccessedCoreAlloc) String() string {
	return fmt.Sprintf("core alloc of %v (node id: %v) in %v at %v (trace: %v)",
		a.Value, a.nodeId, a.Value.Parent().String(), a.Pos, a.trace)
}

// Analyze runs the analysis on all pass through problems specified in the
// config.
func Analyze(s *dataflow.State) (AnalysisResult, error) {
	var res []InvalidAccess
	cache := ptr.NewAliasCache(&s.State)

	for _, spec := range s.Config.DiodonPassThroughProblems {
		state := newState(s, cache, spec)
		invalidAccesses, err := analyze(state)
		if err != nil {
			return AnalysisResult{}, err
		}
		res = append(res, invalidAccesses...)
	}

	return AnalysisResult{InvalidAccesses: res}, nil
}

func analyze(state *state) ([]InvalidAccess, error) {
	var res []InvalidAccess

	// check CoreAlloc function first
	accs, err := analyzeCoreAllocs(state)
	if err != nil {
		state.logger.Errorf("%v\n", err)
	}
	res = append(res, accs...)

	// next check Core Api functions
	coreFuncs := findCoreFuncs(state)
	appFuncs := findAppFuncs(state, coreFuncs)

	for cf, trace := range coreFuncs {
		if shouldFilterCoreAlloc(state.spec, cf.f) {
			continue
		}

		coreTrace := newCoreTrace(trace)
		state.logger.Debugf("Adding allocs in Core for: %v with trace: %v\n", cf, trace)
		addAllocsInCore(state, cf, coreTrace)
	}

	if state.coreAllocIds.Len() == 0 {
		state.logger.Infof("No allocations in the Core found that may leak permissions to a Core API return value")
	}
	state.logger.Debugf("All Core alloc pointer node ids: %v\n", state.coreAllocIds)

	for af, trace := range appFuncs {
		if shouldFilterAppAccess(state.spec, af.f) {
			state.logger.Debugf("Filtering App function according to spec: %v\n", af)
			continue
		}
		state.logger.Debugf("Finding Core accesses for %v (trace: %v)\n", af, trace)
		unvalidatedCoreAccesses := findCoreAccesses(state, af.f, trace)
		for _, unvalidatedAcc := range unvalidatedCoreAccesses {
			if acc, ok := isInvalidCoreAccess(state, unvalidatedAcc); ok {
				state.logger.Debugf("Found %v\n", acc)
				res = append(res, acc)
			}
		}
	}

	return res, nil
}

// isInvalidCoreAccess returns the access and true if acc reads from or writes to a
// heap location allocated in the Core that does not pass through the proper
// return values.
func isInvalidCoreAccess(state *state, acc unvalidatedCoreAccess) (InvalidAccess, bool) {
	var escapedAllocs []EscapedCoreAlloc
	state.logger.Debugf("Validating %v ...\n", acc)
	for _, alloc := range acc.allocs {
		state.logger.Debugf("\talloc: %v\n", alloc)
		var escapes []Escape
		// Find escapes for every Core function in the alloc's trace
		//
		// We need to check all functions reachable from the Core because even
		// functions verified with Gobra can leak references with 0 permissions,
		// and any accesses in the App to these references are unsound
		for _, coreFunc := range alloc.trace {
			if funcDoesNotLeak(state.spec, coreFunc) {
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
		Vals:          acc.vals,
		Pos:           acc.pos,
		EscapedAllocs: escapedAllocs,
		trace:         acc.appTrace,
	}
	if len(escapedAllocs) == 0 {
		return res, false
	}

	return res, true
}

type state struct {
	logger       *config.LogGroup
	spec         config.DiodonPassThroughSpec
	df           *dataflow.State // df is only used to resolve callees - passthru is not a dataflow analysis
	cache        *ptr.AliasCache
	coreAllocIds *intsets.Sparse
	// a single node id can refer to values allocated in multiple calling contexts
	id2allocs map[pointer.NodeID][]allocInCore

	fset *token.FileSet
}

func newState(s *dataflow.State, cache *ptr.AliasCache, spec config.DiodonPassThroughSpec) *state {
	return &state{
		logger:       s.Logger,
		spec:         spec,
		df:           s,
		cache:        cache,
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
	nodeId pointer.NodeID
	trace  coreTrace
}

func (ac allocInCore) String() string {
	return fmt.Sprintf("alloc in core: %v (node id: %v) in %v (trace: %v)", ac.Value, ac.nodeId, ac.Value.Parent(), ac.trace)
}

// addAllocsInCore adds values allocated in the Core with trace to state.
func addAllocsInCore(state *state, cf funcWithCtx, trace coreTrace) {
	if len(trace) == 0 {
		panic(fmt.Errorf("core func has empty trace: %v", cf))
	}

	lang.IterateInstructions(cf.f, func(_ int, instr ssa.Instruction) {
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
			objs := state.cache.Objects(val)
			for obj := range objs {
				nodeId := obj.NodeID()
				alloc := allocInCore{
					Value:  val,
					nodeId: nodeId,
					trace:  trace,
				}
				state.logger.Debugf("Found core alloc: %v at %v\n",
					alloc, state.fset.Position(alloc.Pos()))
				state.coreAllocIds.Insert(int(nodeId))
				state.id2allocs[nodeId] = append(state.id2allocs[nodeId], alloc)
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

// unvalidatedCoreAccess is an instruction in the App that accesses (reads from
// or writes to) a pointer allocated in the core.
// The value is the value written to or read from.
// This instruction's separation logic permissions have not yet been validated
// which is why it's a distinct type.
type unvalidatedCoreAccess struct {
	vals     []accessedVal
	pos      token.Position
	allocs   []AccessedCoreAlloc
	appTrace funcTrace
}

func (ua unvalidatedCoreAccess) String() string {
	var vals []string
	for _, val := range ua.vals {
		vals = append(vals, fmt.Sprintf("%v (type %v)", val.String(), val.Type().String()))
	}
	parent := ua.vals[0].Parent()

	return fmt.Sprintf("(unvalidated) access in app to core alloc: via values %v in %v at %v of %d allocs (trace: %v)",
		strings.Join(vals, ", "), parent, ua.pos, len(ua.allocs), ua.appTrace)
}

type accessedVal struct {
	ssa.Value
	nodeId pointer.NodeID
}

func (av accessedVal) String() string {
	return fmt.Sprintf("%v (node id: %v)", av.Value, av.nodeId)
}

type coreTrace funcTrace

func newCoreTrace(trace funcTrace) coreTrace {
	ct := coreTrace{}
	seenCore := false
	for _, tf := range trace {
		if tf.ctx == core {
			seenCore = true
		}

		if seenCore {
			ct = append(ct, tf)
		}
	}

	return ct
}

func findCoreAccesses(state *state, appFunc *ssa.Function, appTrace funcTrace) []unvalidatedCoreAccess {
	var res []unvalidatedCoreAccess
	lang.IterateInstructions(appFunc, func(_ int, instr ssa.Instruction) {
		if !instr.Pos().IsValid() {
			return
		}

		pos := state.fset.Position(instr.Pos())
		var valsAccessed []ssa.Value
		if write, ok := ptr.PtrWrittenToPtr(instr, pos); ok {
			valsAccessed = append(valsAccessed, write.Target)
		} else if write, ok := ptr.PtrWrittenTo(instr, pos); ok {
			valsAccessed = append(valsAccessed, write.Target)
		} else if read, ok := ptr.PtrsReadFrom(instr, pos); ok {
			for _, val := range read.Values {
				valsAccessed = append(valsAccessed, val)
			}
		}

		var allocs []AccessedCoreAlloc
		var accessedVals []accessedVal
		seenAllocs := make(map[*allocInCore]struct{}) // need pointer to allocInCore to be hashable
		for _, valAccessed := range valsAccessed {
			objs := state.cache.Objects(valAccessed)
			for obj := range objs {
				nodeId := obj.NodeID()
				if state.coreAllocIds.Has(int(nodeId)) {
					aics, ok := state.id2allocs[nodeId]
					if !ok {
						panic(fmt.Errorf(
							"failed to find allocs in core for access %v at %v to node id: %v",
							instr, pos, nodeId))
					}
					found := false
					for _, aic := range aics {
						if _, ok := seenAllocs[&aic]; ok {
							continue
						}
						seenAllocs[&aic] = struct{}{}
						alloc := AccessedCoreAlloc{
							Value:  aic.Value,
							Pos:    state.fset.Position(aic.Value.Pos()),
							trace:  aic.trace,
							nodeId: nodeId,
						}
						allocs = append(allocs, alloc)
						found = true
					}

					if found {
						accessedVals = append(accessedVals, accessedVal{valAccessed, nodeId})
					}
				}
			}
		}
		if len(allocs) > 0 {
			acc := unvalidatedCoreAccess{vals: accessedVals, pos: pos, allocs: allocs, appTrace: appTrace}
			res = append(res, acc)
		}
	})

	return res
}

type funcWithCtx struct {
	f   *ssa.Function
	ctx funcContext
}

func (cf funcWithCtx) String() string {
	return fmt.Sprintf("%s (in %s)", cf.f.String(), cf.ctx.String())
}

// funcTrace is the calling context of a function from the program root.
//
// It represents reachability, NOT a list of calls that actually may occur
// because we do not traverse callees in the order they are called.
// Doing so would require a much more heavyweight dataflow-like analysis.
type funcTrace []funcWithCtx

func (t funcTrace) String() string {
	if len(t) == 0 {
		return "<empty>"
	}

	var s []string
	for _, f := range t {
		s = append(s, f.String())
	}

	return strings.Join(s, "->")
}

// elt is a node in the callgraph.
type elt struct {
	*callgraph.Node
	context funcContext
}

// eltctx is an elt with more context.
type eltctx struct {
	elt
	trace  funcTrace
	indent int // indent is only used for debugging
}

type funcToTrace map[funcWithCtx]funcTrace

// findCoreFuncs returns a map from Core func to its trace (calling context).
// A function is in the Core if it is reachable from any Core function.
func findCoreFuncs(state *state) funcToTrace {
	cfs := make(funcToTrace)
	// Traverse callgraph with DFS because once a function is called in a Core context,
	// all of its transitive callees are in the Core context as well.
	cg := state.cache.PtrState.PointerAnalysis.CallGraph
	root := eltctx{
		elt:    elt{Node: cg.Root, context: app},
		trace:  nil,
		indent: 0,
	}
	stack := []eltctx{root}
	seen := map[elt]bool{}
	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		if seen[cur.elt] {
			continue
		}
		seen[cur.elt] = true

		// if !state.df.IsReachableFunction(cur.Func) {
		// 	continue
		// }

		cf := funcWithCtx{
			f:   cur.Func,
			ctx: cur.context,
		}

		switch cur.context {
		case unknown:
			// unknown function called in Core context is a Core function
			if isCalledInCoreContext(cur.trace) {
				cfs[cf] = cur.trace
			}
		case core:
			cfs[cf] = cur.trace
		case app:
			// App function called in Core context is a Core function
			if isCalledInCoreContext(cur.trace) {
				cfs[cf] = cur.trace
			}
		default:
			panic(fmt.Errorf("invalid context for callgraph node %v: %v", cur.Node, cur.context))
		}

		if state.logger.LogsTrace() {
			state.logger.Tracef(
				"%s%v: (core trace: %v)\n",
				strings.Repeat("  ", cur.indent),
				cf,
				cur.trace)
		}

		for _, edge := range cur.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}

			nextCtx := contextOf(state.spec, edge.Callee.Func)
			nextCf := funcWithCtx{
				f:   edge.Callee.Func,
				ctx: nextCtx,
			}
			// NOTE need to copy slice to avoid aliasing issues
			nextTrace := make(funcTrace, len(cur.trace))
			copy(nextTrace, cur.trace)
			nextTrace = append(nextTrace, nextCf)
			stack = append(stack, eltctx{
				elt: elt{
					Node:    edge.Callee,
					context: nextCtx,
				},
				trace:  nextTrace,
				indent: cur.indent + 1,
			})
		}
	}

	return cfs
}

func isCalledInCoreContext(trace funcTrace) bool {
	for _, tf := range trace {
		if tf.ctx == core {
			return true
		}
	}

	return false
}

// findAppFuncs returns a map from a function in the App to its trace (calling
// context).
func findAppFuncs(state *state, cfs funcToTrace) funcToTrace {
	afs := make(funcToTrace)
	cg := state.cache.PtrState.PointerAnalysis.CallGraph
	root := eltctx{
		elt:    elt{Node: cg.Root, context: app},
		trace:  nil,
		indent: 0,
	}
	stack := []eltctx{root}
	seen := map[elt]bool{}
	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		if seen[cur.elt] {
			continue
		}
		seen[cur.elt] = true

		// if !state.df.IsReachableFunction(cur.Func) {
		// 	continue
		// }

		af := funcWithCtx{
			f:   cur.Func,
			ctx: cur.context,
		}

		switch cur.context {
		case unknown, app:
			// An App function that has been called in a Core calling context is
			// not added to the list of App functions because an access to
			// memory inside the function is still in the Core context (which
			// has permissions), not the App.
			//
			// NOTE this is unsound and only done to reduce false-positives
			if _, ok := cfs[af]; ok {
				break
			}

			// HACK special case for godebugs package: this is only used
			// internally by the Go compiler for debug info at runtime and
			// should not be considered part of the accessible heap locations of
			// the program
			if lang.PackageNameFromFunction(af.f) == "internal/godebugs" {
				continue
			}

			afs[af] = cur.trace
		case core:
			// A Core function must never be analyzed as an App function:
			// stop searching its callees
			continue
		default:
			panic(fmt.Errorf("invalid context for callgraph node %v: %v", cur.Node, cur.context))
		}

		if state.logger.LogsTrace() {
			state.logger.Tracef(
				"%s(%s) %v: (app trace: %v)\n",
				strings.Repeat("  ", cur.indent),
				cur.context.String(),
				cur.Func.String(),
				cur.trace)
		}

		for _, edge := range cur.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}

			nextCtx := contextOf(state.spec, edge.Callee.Func)
			nextAf := funcWithCtx{
				f:   edge.Callee.Func,
				ctx: nextCtx,
			}
			// NOTE need to copy slice to avoid aliasing issues
			nextTrace := make(funcTrace, len(cur.trace))
			copy(nextTrace, cur.trace)
			nextTrace = append(nextTrace, nextAf)
			stack = append(stack, eltctx{
				elt: elt{
					Node:    edge.Callee,
					context: nextCtx,
				},
				trace:  nextTrace,
				indent: cur.indent + 1,
			})
		}
	}

	return afs
}

func analyzeCoreAllocs(state *state) ([]InvalidAccess, error) {
	info := allCoreAllocCalls(state)
	cid := state.spec.CoreAllocFunction
	var rets []valWithPos
	for _, call := range info.calls {
		vals := returnedVals(state, cid, call)
		rets = append(rets, vals...)
	}
	if len(rets) == 0 {
		return nil, fmt.Errorf("failed to find any returned values in calls to Core Alloc function: %v", cid)
	}

	var res []InvalidAccess
	for _, f := range info.callees {
		for _, ret := range rets {
			pos := ret.Pos
			objs := state.cache.Objects(ret.Value)
			for obj := range objs {
				acc := AccessedCoreAlloc{
					Value:  ret.Value,
					Pos:    pos,
					trace:  nil,
					nodeId: obj.NodeID(),
				}
				escs := findEscapes(state, f, acc)
				if len(escs) > 0 {
					state.logger.Warnf("Core Instance allocation escaped CoreAlloc function: %v", escs)
					ia := InvalidAccess{
						Vals:          []accessedVal{{Value: ret.Value, nodeId: obj.NodeID()}},
						Pos:           pos,
						trace:         nil,
						EscapedAllocs: []EscapedCoreAlloc{{AccessedCoreAlloc: acc, Escapes: escs}},
					}
					res = append(res, ia)
				}
			}
		}
	}

	return res, nil
}

// valWithPos is needed because ssa.Extract sometimes doesn't have a valid
// position.
type valWithPos struct {
	ssa.Value
	Pos token.Position
}

func returnedVals(state *state, funcId config.CodeIdentifier, call ssa.CallInstruction) []valWithPos {
	var vals []valWithPos
	// If the call returns a tuple, add the respective return value
	// extract instructions to vals, otherwise add the result of the
	// call
	sig := call.Value().Common().Signature()
	isTupleReturn := sig.Results().Len() > 1
	if isTupleReturn {
		if call.Value().Referrers() == nil {
			panic(fmt.Errorf(
				"no referrers for call with multiple returns: %v (signature: %v)",
				call, sig))
		}

		for _, refInstr := range *call.Value().Referrers() {
			extract, ok := refInstr.(*ssa.Extract)
			if !ok {
				continue
			}
			for _, retIdx := range funcId.ReturnIndices {
				if extract.Index == retIdx {
					vals = append(vals, valWithPos{extract, state.fset.Position(call.Pos())})
				}
			}
		}
	} else {
		vals = append(vals, valWithPos{call.Value(), state.fset.Position(call.Pos())})
	}

	return vals
}

type coreAllocCallInfo struct {
	calls   []ssa.CallInstruction
	callees []*ssa.Function
}

func allCoreAllocCalls(state *state) coreAllocCallInfo {
	var calls []ssa.CallInstruction
	var coreAllocCallees []*ssa.Function
	for f := range state.df.ReachableFunctions() {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				return
			}

			callees, err := state.df.ResolveCallee(call, true)
			if err != nil {
				panic(fmt.Errorf("failed to resolve callees of function call: %v", call))
			}
			if len(callees) == 0 {
				return
			}

			// All possible callees must be Core Alloc function
			allCoreAlloc := true
			for callee := range callees {
				allCoreAlloc = allCoreAlloc && state.spec.CoreAllocFunction.MatchPackageAndMethod(callee)
			}
			if !allCoreAlloc {
				return
			}

			state.logger.Debugf("Found call to Core Alloc function: %v\n", call)
			calls = append(calls, call)
			coreAllocCallees = append(coreAllocCallees, maps.Keys(callees)...)
		})
	}

	return coreAllocCallInfo{calls: calls, callees: coreAllocCallees}
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
	for _, funcId := range spec.CoreApiFunctions {
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
