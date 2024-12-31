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

// CoreAlloc is a pointer allocated in the Core that is accessed in the App.
type CoreAlloc struct {
	ssa.Value
	Pos token.Position
}

func (a CoreAlloc) String() string {
	return fmt.Sprintf("alloc in core of %v at %v", a.Value, a.Pos)
}

// escape is a value that results in a CoreAlloc heap permission "escaping" a
// function.
type escape struct {
	ssa.Value
	Pos token.Position
}

func (e escape) String() string {
	return fmt.Sprintf("escaped value %v at %v", e.Value, e.Pos)
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

// findEscapes returns a map from Core allocations in allocs to all the values whose
// permissions are a subset of the allocated value's permissions, and "escape"
// the function f.
//
// This is a purely intra-procedural analysis.
//
//gocyclo:ignore
func findEscapes(cache *ptr.AliasCache, f *ssa.Function, allocs []CoreAlloc, allowedReturns map[*ssa.Return]struct{}) map[CoreAlloc][]escape {
	res := make(map[CoreAlloc][]escape)
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		pos := cache.PtrState.Program.Fset.Position(instr.Pos())
		switch instr := instr.(type) {
		case *ssa.Store, *ssa.MapUpdate, *ssa.Send:
			if write, ok := ptr.PtrWrittenToPtr(instr, pos); ok {
				for _, alloc := range allocs {
					if hasPermissionsOf(cache, write.Value, alloc) {
						esc := escape{
							Value: write.Value,
							Pos:   pos,
						}
						res[alloc] = append(res[alloc], esc)
					}
				}
			}
		case *ssa.MakeClosure:
			for _, freeVar := range instr.Bindings {
				for _, alloc := range allocs {
					if hasPermissionsOf(cache, freeVar, alloc) {
						if !pos.IsValid() {
							pos = cache.PtrState.Program.Fset.Position(freeVar.Pos())
						}
						esc := escape{
							Value: freeVar,
							Pos:   pos,
						}
						res[alloc] = append(res[alloc], esc)
					}
				}
			}
		case ssa.CallInstruction:
			args := lang.GetArgs(instr)
			for _, arg := range args {
				for _, alloc := range allocs {
					if hasPermissionsOf(cache, arg, alloc) {
						esc := escape{
							Value: arg,
							Pos:   pos,
						}
						res[alloc] = append(res[alloc], esc)
					}
				}
			}
		case *ssa.Return:
			if _, ok := allowedReturns[instr]; ok {
				// skip analyzing if the return is allowed
				return
			}

			for _, r := range instr.Results {
				for _, alloc := range allocs {
					if hasPermissionsOf(cache, r, alloc) {
						esc := escape{
							Value: r,
							Pos:   pos,
						}
						res[alloc] = append(res[alloc], esc)
					}
				}
			}
		}
	})

	return res
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
func hasPermissionsOf(cache *ptr.AliasCache, val ssa.Value, alloc CoreAlloc) bool {
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

type coreFunc struct {
	f *ssa.Function
	// allAllocIds is the set of all node ids of pointers allocated in f
	allAllocIds *intsets.Sparse
	allocs      []ssa.Instruction
}

func (cf coreFunc) String() string {
	return fmt.Sprintf("core func %v with %d allocated objects", cf.f, cf.allAllocIds.Len())
}

func newCoreFunc(cache *ptr.AliasCache, f *ssa.Function, trace trace) coreFunc {
	var allocs []ssa.Instruction
	ids := &intsets.Sparse{}
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		if alloc, ok := instr.(*ssa.Alloc); ok {
			// alloc can only escape a function if it is on the heap
			if !alloc.Heap {
				return
			}
		}

		switch instr.(type) {
		case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
			val := instr.(ssa.Value) // safe conversion
			allocs = append(allocs, instr)
			objs := cache.Objects(val)
			for obj := range objs {
				ids.Insert(int(obj.NodeID()))
			}
		}
	})

	return coreFunc{
		f:           f,
		allAllocIds: ids,
		allocs:      allocs,
	}
}

// trace is the Core function trace from a Core API function to the function
// that allocates a CoreAlloc.
//
// This is also the list of functions the CoreAlloc must not "escape" from.
type trace []*ssa.Function

// unvalidatedCoreAccess is an instruction in the App that accesses (reads from
// or writes to) a pointer allocated in the core.
// This instruction's separation logic permissions have not yet been validated
// which is why it's a distinct type.
type unvalidatedCoreAccess struct {
	ssa.Instruction
	pos    token.Position
	trace  trace
	allocs []CoreAlloc
}

func findCoreAccesses(cache *ptr.AliasCache, appFunc *ssa.Function, trace trace, coreAllocIds *intsets.Sparse, id2alloc map[pointer.NodeID]ssa.Value) []unvalidatedCoreAccess {
	var res []unvalidatedCoreAccess
	lang.IterateInstructions(appFunc, func(_ int, instr ssa.Instruction) {
		pos := cache.PtrState.Program.Fset.Position(instr.Pos())
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
		if len(accessedVals) == 0 {
			return
		}

		var allocs []CoreAlloc
		for _, accessedVal := range accessedVals {
			objs := cache.Objects(accessedVal)
			for obj := range objs {
				if coreAllocIds.Has(int(obj.NodeID())) {
					allocVal, ok := id2alloc[obj.NodeID()]
					if !ok {
						panic(fmt.Errorf("failed to find alloc for access %v at %v to node id: %v", instr, pos, obj.NodeID()))
					}
					alloc := CoreAlloc{Value: allocVal, Pos: cache.PtrState.Program.Fset.Position(allocVal.Pos())}
					allocs = append(allocs, alloc)
				}
			}
		}
		if len(allocs) > 0 {
			acc := unvalidatedCoreAccess{Instruction: instr, pos: pos, trace: trace, allocs: allocs}
			res = append(res, acc)
		}
	})

	return res
}

type invalidCoreAccess struct {
	ssa.Instruction
	pos    token.Position
	trace  *trace
	allocs []CoreAlloc
}

func isInvalidCoreAccess(acc unvalidatedCoreAccess, alloc CoreAlloc) (invalidCoreAccess, bool) {
	return invalidCoreAccess{}, false
}

// elt is a node in the callgraph.
type elt struct {
	*callgraph.Node
	context context // context is the context of the node
}

// eltctx is an elt with more context.
type eltctx struct {
	elt
	trace  trace
	indent int // indent is only used for debugging
}

// analyze adds core and app functions to state.
//
// A function is in the app if it is reachable from the main function
// (callgraph root) and not from any core function.
// A function is in the core if it is reachable from any core function.
func analyze(state *state, spec config.DiodonPassThroughSpec) []CoreWrite {
	var res []CoreWrite

	// traverse callgraph with DFS because once a function is called in a core context,
	// all of its transitive callees are in the core context as well
	// TODO what about callbacks from the core into the app?
	cg := state.cache.PtrState.PointerAnalysis.CallGraph
	root := eltctx{elt: elt{Node: cg.Root, context: app}, trace: nil, indent: 0}
	stack := []eltctx{root}
	seen := map[elt]bool{}
	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		if seen[cur.elt] {
			continue
		}

		if state.logger.LogsDebug() {
			state.logger.Debugf(
				"%s(%s) %v: %v\n",
				strings.Repeat("  ", cur.indent),
				cur.context.String(),
				cur.Func.String(),
				cur.trace)
		}

		switch cur.context {
		case core:
		case app:
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
			if nextCtx == app {
				nextCtx = contextOf(spec, edge.Callee.Func)
				if nextCtx == unknown {
					nextCtx = cur.context
				}
			}

			stack = append(stack, eltctx{
				elt:    elt{Node: edge.Callee, context: nextCtx},
				trace:  append(cur.trace, edge.Callee.Func),
				indent: cur.indent + 1,
			})
		}
	}

	return res
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
