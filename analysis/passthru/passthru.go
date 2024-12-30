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
	// InvalidWrites is all the writes in the Application to a pointer allocated
	// in the Core without correct separation logic permissions.
	InvalidWrites []CoreWrite
}

// CoreWrite is a write in the app to a pointer allocated in the Core.
type CoreWrite struct {
	ptr.Write
	Alloc CoreAlloc
	id    pointer.NodeID
}

func (cw CoreWrite) String() string {
	return fmt.Sprintf("core %v written to in the app via: %v", cw.Alloc, cw.Write)
}

// CoreAlloc is a value allocated in the Core.
type CoreAlloc struct {
	ssa.Value
	Pos token.Position
	// trace is the calling context of the allocation instruction's parent function.
	// It only contains the Core API functions in the calling context.
	trace trace
}

func (a CoreAlloc) String() string {
	return fmt.Sprintf("alloc of %v (ctx: %s) at %v", a.Value, a.trace.String(), a.Pos)
}

// Analyze runs the analysis on all pass through problems specified in the
// config.
func Analyze(s *ptr.State) (AnalysisResult, error) {
	var res []CoreWrite
	cache := ptr.NewAliasCache(s)

	for _, spec := range s.Config.DiodonPassThroughProblems {
		state := newState(s, cache, spec)
		invalidWrites := analyze(state, spec)
		res = append(res, invalidWrites...)
	}

	return AnalysisResult{InvalidWrites: res}, nil
}

type state struct {
	logger         *config.LogGroup
	spec           config.DiodonPassThroughSpec
	cache          *ptr.AliasCache
	coreAllocAddrs *intsets.Sparse
	coreAllocs     map[pointer.NodeID]CoreAlloc
	coreWrites     []CoreWrite
}

func newState(s *ptr.State, cache *ptr.AliasCache, spec config.DiodonPassThroughSpec) *state {
	return &state{
		logger:         s.Logger,
		spec:           spec,
		cache:          cache,
		coreAllocAddrs: &intsets.Sparse{},
		coreAllocs:     make(map[pointer.NodeID]CoreAlloc),
		coreWrites:     nil,
	}
}

// trace is the trace of Core API function returns that a function was called from.
// The first element in the trace is the deepest function in the call stack.
type trace []coreRet

type coreRet struct {
	rets    []*ssa.Return
	nodeIds *intsets.Sparse
}

func (cr coreRet) String() string {
	if len(cr.rets) == 0 {
		return "<no returns>"
	}
	return fmt.Sprintf("%s.rets[0:%d]", cr.rets[0].Parent().String(), len(cr.rets))
}

func newCoreRet(cache *ptr.AliasCache, f *ssa.Function) coreRet {
	rets := returnNodes(f)
	ids := retIds(cache, rets)
	return coreRet{rets: rets, nodeIds: ids}
}

func (t trace) String() string {
	if len(t) == 0 {
		return "<no trace>"
	}

	s := &strings.Builder{}
	for i := len(t) - 1; i >= 0; i-- {
		s.WriteString(t[i].String())
		if i != 0 {
			s.WriteString(" -> ")
		}
	}

	return s.String()
}

// elt is a node in the callgraph.
type elt struct {
	*callgraph.Node
	context context // context is the context of the node
}

// eltctx is an elt with more context.
type eltctx struct {
	elt
	trace  trace // trace is the node's calling context
	indent int   // indent is only used for debugging
}

type coreFunc struct {
	f      *ssa.Function
	allocs map[pointer.NodeID]CoreAlloc
	ret    coreRet
}

func (cf coreFunc) String() string {
	return fmt.Sprintf("core func %v with allocs: %v", cf.f, cf.allocs)
}

func newCoreFunc(cache *ptr.AliasCache, f *ssa.Function) *coreFunc {
	return &coreFunc{
		f:      f,
		allocs: make(map[pointer.NodeID]CoreAlloc),
		ret:    newCoreRet(cache, f),
	}
}

// algo:
// traverse the program (monotonic?)
// if alloc in core: add to temp store of allocs in the current core api function
// if return from core api func: store return + allocated heap locations returned, add to trace
// if read/write in app: check that the heap location read/written is in the allocated heap locations in the trace
//
// what happens when a core func is called twice in the app?

// analyze adds core and app functions to state.
//
// A function is in the app if it is reachable from the main function
// (callgraph root) and not from any core function.
// A function is in the core if it is reachable from any core function.
func analyze(state *state, spec config.DiodonPassThroughSpec) []CoreWrite {
	var res []CoreWrite
	cg := state.cache.PtrState.PointerAnalysis.CallGraph

	// curCoreApiFunc is the Core API function's allocations and returns that
	// are reachable in the current function being visited
	var curCoreApiFunc *coreFunc
	// traverse callgraph with DFS because once a function is called in a core context,
	// all of its transitive callees are in the core context as well
	// TODO what about callbacks from the core into the app?
	root := eltctx{elt: elt{Node: cg.Root, context: app}, trace: nil, indent: 0}
	stack := []eltctx{root}
	seen := map[elt]bool{}
	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		if seen[cur.elt] {
			continue
		}

		// if state.logger.LogsDebug() {
		// 	if curCoreApiFunc == nil {
		// 		state.logger.Debugf(
		// 			"%s(%s) %v without core func\n",
		// 			strings.Repeat("  ", cur.indent),
		// 			cur.context.String(),
		// 			cur.Func.String())
		// 	} else {
		// 		state.logger.Debugf(
		// 			"%s(%s) %v with core func: %v\n",
		// 			strings.Repeat("  ", cur.indent),
		// 			cur.context.String(),
		// 			cur.Func.String(),
		// 			curCoreApiFunc.f)
		// 	}
		// }

		if isCoreApiFunc(spec, cur.Func) {
			cur.context = core
			curCoreApiFunc = newCoreFunc(state.cache, cur.Func)
		}

		switch cur.context {
		case core:
			addCoreAllocs(state, curCoreApiFunc, cur.Func)
		case app:
			invalidWrites := checkWrites(state, curCoreApiFunc, cur.Func)
			res = append(res, invalidWrites...)
		default:
			panic(fmt.Errorf("invalid context for callgraph node %v: %v", cur.Node, cur.context))
		}

		for _, edge := range cur.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}

			ctx := cur.context
			// only change the context if it's not in the core
			if ctx == app {
				ctx = contextOf(spec, edge.Callee.Func)
				if ctx == unknown {
					ctx = cur.context
				}
			}

			stack = append(stack, eltctx{elt: elt{Node: edge.Callee, context: ctx}, trace: cur.trace, indent: cur.indent + 1})
			seen[elt{Node: cur.Node, context: cur.context}] = true
		}
	}

	return res
}

func addCoreAllocs(state *state, cf *coreFunc, f *ssa.Function) {
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		switch alloc := instr.(type) {
		case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
			if ok := returnedFromCore(state, cf, alloc.(ssa.Value)); ok {
				state.logger.Debugf("%v returned from core: %v\n", alloc, cf.ret)
			}
		}
	})
}

func returnedFromCore(state *state, cf *coreFunc, val ssa.Value) bool {
	returned := false
	pos := state.cache.PtrState.Program.Fset.Position(val.Pos())
	objs := state.cache.Objects(val) // safe type conversion
	for obj := range objs {
		if cf.ret.nodeIds.Has(int(obj.NodeID())) {
			cf.allocs[obj.NodeID()] = CoreAlloc{Value: val, Pos: pos, trace: nil}
			returned = true
		}
	}

	return returned
}

func coreApiRetHeapLocs(tr trace) *intsets.Sparse {
	ids := &intsets.Sparse{}
	for _, n := range tr {
		ids.Union(ids, n.nodeIds)
	}

	return ids
}

func retIds(cache *ptr.AliasCache, rets []*ssa.Return) *intsets.Sparse {
	ids := &intsets.Sparse{}
	for _, ret := range rets {
		for _, valReturned := range ret.Results {
			objs := cache.Objects(valReturned)
			for obj := range objs {
				for _, id := range obj.NodeIDs() {
					ids.Insert(int(id))
				}
			}
		}
	}

	return ids
}

func checkWrites(state *state, cf *coreFunc, f *ssa.Function) []CoreWrite {
	if cf == nil {
		return nil
	}

	var invalidWrites []CoreWrite
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		pos := state.cache.PtrState.Program.Fset.Position(instr.Pos())
		if !pos.IsValid() {
			return
		}
		if write, ok := ptr.PtrWrittenTo(instr, pos); ok {
			objs := state.cache.Objects(write.Target)
			for obj := range objs {
				if cw, ok := allocatedInCore(write, cf, obj); ok {
					state.logger.Debugf("found %v\n", cw)
					if !isValidCoreWrite(state, cw) {
						invalidWrites = append(invalidWrites, cw)
					}
				}
			}
		}
	})

	return invalidWrites
}

func isValidCoreWrite(state *state, write CoreWrite) bool {
	if isFalsePositive(state.spec, write.Alloc) {
		state.logger.Debugf("False positive: %v\n", write)
		return true
	}

	coreApiRetIds := coreApiRetHeapLocs(write.Alloc.trace)
	if !coreApiRetIds.Has(int(write.id)) {
		return false
	}

	state.logger.Infof("Safe core write: %v\n", write)
	return true
}

func isFalsePositive(spec config.DiodonPassThroughSpec, alloc CoreAlloc) bool {
	for _, filterId := range spec.Filters {
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
	unknown = iota
	core
	app
)

func (c context) String() string {
	switch c {
	case unknown:
		return "Unknown"
	case core:
		return "Core"
	case app:
		return "App"
	default:
		panic("invalid context")
	}
}

func allocatedInCore(write ptr.Write, cf *coreFunc, obj *pointer.Object) (CoreWrite, bool) {
	alloc, ok := cf.allocs[obj.NodeID()]
	if !ok {
		return CoreWrite{Write: write, id: obj.NodeID()}, false
	}

	cw := CoreWrite{Write: write, Alloc: alloc, id: obj.NodeID()}
	if !cf.ret.nodeIds.Has(int(obj.NodeID())) {
		return cw, false
	}

	return cw, true
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

	// TODO don't hardcode
	var appPkgs = []string{
		"command-line-arguments",
		"dh-gobra",
	}
	for _, appPkg := range appPkgs {
		pkg := lang.PackageNameFromFunction(f)
		if strings.HasPrefix(pkg, appPkg) {
			return app
		}
	}

	// TODO are stdlib instructions in the App?
	// What about calling context? Should all function calls in the core be inlined?

	return unknown
}

// ReportResults returns res as a formatted string and true if the analysis failed.
func ReportResults(res AnalysisResult) (string, bool) {
	failed := false
	report := &strings.Builder{}
	if len(res.InvalidWrites) > 0 {
		report.WriteString(formatutil.Red("Invalid permissions to core allocations found:\n"))
		failed = true
	} else {
		report.WriteString(formatutil.Green("All core allocation permissions are valid\n"))
	}
	for _, w := range res.InvalidWrites {
		report.WriteString(fmt.Sprintf("\t%v\n", w))
	}

	return report.String(), failed
}
