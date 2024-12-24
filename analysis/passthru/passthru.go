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
}

func (a CoreAlloc) String() string {
	return fmt.Sprintf("alloc of %v at %v", a.Value, a.Pos)
}

// Analyze runs the analysis.
func Analyze(s *ptr.State) (AnalysisResult, error) {
	var res []CoreWrite
	cache := ptr.NewAliasCache(s)

	for _, spec := range s.Config.DiodonPassThroughProblems {
		state := newState(s, cache, spec)
		coreFuncs, err := coreApiFuncs(spec, state.coreFuncs)
		if err != nil {
			return AnalysisResult{}, fmt.Errorf("failed to find all core api functions: %v", err)
		}

		rets := returnNodes(coreFuncs)
		coreApiRetIds := retIds(state.cache, rets)
		invalidWrites := checkWrites(state, coreApiRetIds)
		res = append(res, invalidWrites...)
	}

	return AnalysisResult{InvalidWrites: res}, nil
}

func retIds(cache *ptr.AliasCache, rets []*ssa.Return) map[pointer.NodeID]struct{} {
	ids := make(map[pointer.NodeID]struct{}, len(rets))
	for _, ret := range rets {
		for _, valReturned := range ret.Results {
			objs := cache.Objects(valReturned)
			for obj := range objs {
				for _, id := range obj.NodeIDs() {
					ids[id] = struct{}{}
				}
			}
		}
	}

	return ids
}

func checkWrites(state *state, coreApiRetIds map[pointer.NodeID]struct{}) []CoreWrite {
	var invalidWrites []CoreWrite
	for f := range state.appFuncs {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			pos := state.cache.PtrState.Program.Fset.Position(instr.Pos())
			if !pos.IsValid() {
				return
			}
			if write, ok := ptr.PtrWrittenTo(instr, pos); ok {
				objs := state.cache.Objects(write.Target)
				for obj := range objs {
					if allocatedInApp(state, obj) {
						// ok
					} else if cw, ok := allocatedInCore(state, write, obj); ok {
						if !isValidCoreWrite(state, cw, coreApiRetIds) {
							invalidWrites = append(invalidWrites, cw)
						}
					} else {
						// TODO is this sound?
						// panic(fmt.Errorf("write %v does not have a corresponding alloc", write, write.Target, write.Target.Type(), write.Pos))
					}
				}
			}
		})
	}

	return invalidWrites
}

func isValidCoreWrite(state *state, write CoreWrite, coreApiRetIds map[pointer.NodeID]struct{}) bool {
	if isFalsePositive(state.spec, write.Alloc) {
		state.logger.Debugf("False positive: %v\n", write)
		return true
	}
	if _, ok := coreApiRetIds[write.id]; !ok {
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

func returnNodes(funcs map[*ssa.Function]bool) []*ssa.Return {
	var rets []*ssa.Return
	for f := range funcs {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			if ret, ok := instr.(*ssa.Return); ok {
				rets = append(rets, ret)
			}
		})
	}

	return rets
}

// appWrite is a write to a pointer allocated in the app.
type appWrite struct {
	ptr.Write
	id pointer.NodeID
}

type state struct {
	logger         *config.LogGroup
	spec           config.DiodonPassThroughSpec
	cache          *ptr.AliasCache
	appFuncs       map[*ssa.Function]bool
	coreFuncs      map[*ssa.Function]bool
	appAllocAddrs  *intsets.Sparse
	coreAllocAddrs *intsets.Sparse
	coreAllocs     map[pointer.NodeID]CoreAlloc
	appWrites      []appWrite
	coreWrites     []CoreWrite
}

func newState(s *ptr.State, cache *ptr.AliasCache, spec config.DiodonPassThroughSpec) *state {
	state := &state{
		logger:         s.Logger,
		spec:           spec,
		cache:          cache,
		appFuncs:       make(map[*ssa.Function]bool),
		coreFuncs:      make(map[*ssa.Function]bool),
		appAllocAddrs:  &intsets.Sparse{},
		coreAllocAddrs: &intsets.Sparse{},
		coreAllocs:     make(map[pointer.NodeID]CoreAlloc),
		appWrites:      nil,
		coreWrites:     nil,
	}
	addFuncs(state, spec)
	addAllocs(state)

	return state
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

// addFuncs adds core and app functions to state.
//
// A function is in the app if it is reachable from the main function
// (callgraph root) and not from any core function.
// A function is in the core if it is reachable from any core function.
func addFuncs(state *state, spec config.DiodonPassThroughSpec) {
	cg := state.cache.PtrState.PointerAnalysis.CallGraph
	type elt struct {
		*callgraph.Node
		context context // context is the context of the node
		indent  int     // indent is only used for debugging
	}
	// traverse callgraph with DFS because once a function is called in a core context,
	// all of its transitive callees are in the core context as well
	// TODO what about callbacks from the core into the app?
	root := elt{Node: cg.Root, context: app, indent: 0}
	stack := []elt{root}
	seen := map[elt]bool{}
	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]

		if seen[elt{Node: cur.Node, context: cur.context}] {
			continue
		}

		// uncomment for debugging
		// fmt.Printf("%s(%s) %v\n", strings.Repeat("  ", cur.indent), cur.context.String(), cur.Func.String())
		switch cur.context {
		case core:
			state.coreFuncs[cur.Func] = true
		case app:
			state.appFuncs[cur.Func] = true
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

			stack = append(stack, elt{Node: edge.Callee, context: ctx, indent: cur.indent + 1})
			seen[elt{Node: cur.Node, context: cur.context}] = true
		}
	}

	if len(state.coreFuncs) == 0 {
		panic("no core funcs found")
	}
	if len(state.appFuncs) == 0 {
		panic("no app funcs found")
	}
}

func addAllocs(state *state) {
	for f := range state.coreFuncs {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			switch alloc := instr.(type) {
			case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
				pos := state.cache.PtrState.Program.Fset.Position(alloc.Pos())
				objs := state.cache.Objects(alloc.(ssa.Value)) // safe type conversion
				for obj := range objs {
					state.coreAllocAddrs.Insert(int(obj.NodeID()))
					state.coreAllocs[obj.NodeID()] = CoreAlloc{Value: alloc.(ssa.Value), Pos: pos}
				}
			}
		})
	}
	if state.coreAllocAddrs.IsEmpty() {
		panic("no core allocs found")
	}

	for f := range state.appFuncs {
		lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
			switch alloc := instr.(type) {
			case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
				objs := state.cache.Objects(alloc.(ssa.Value)) // safe type conversion
				for obj := range objs {
					state.appAllocAddrs.Insert(int(obj.NodeID()))
				}
			}
		})
	}
	if state.appAllocAddrs.IsEmpty() {
		panic("no app allocs found")
	}

	// any addresses common to core and alloc should be removed from alloc
	common := &intsets.Sparse{}
	common.Intersection(state.coreAllocAddrs, state.appAllocAddrs)
	state.appAllocAddrs.Difference(state.appAllocAddrs, common)
}

func allocatedInApp(state *state, obj *pointer.Object) bool {
	return state.appAllocAddrs.Has(int(obj.NodeID()))
}

func allocatedInCore(state *state, write ptr.Write, obj *pointer.Object) (CoreWrite, bool) {
	alloc, ok := state.coreAllocs[obj.NodeID()]
	if !ok {
		return CoreWrite{Write: write, id: obj.NodeID()}, false
	}

	cw := CoreWrite{Write: write, Alloc: alloc, id: obj.NodeID()}
	if !state.coreAllocAddrs.Has(int(obj.NodeID())) {
		return cw, false
	}

	return cw, true
}

// TODO don't hardcode
var appPkgs = []string{
	"command-line-arguments",
	"dh-gobra",
}

func contextOf(spec config.DiodonPassThroughSpec, fn *ssa.Function) context {
	for _, coreApiFuncId := range spec.CoreApiFunctions {
		if coreApiFuncId.MatchPackageAndMethod(fn) {
			return core
		}
	}

	for _, appPkg := range appPkgs {
		pkg := lang.PackageNameFromFunction(fn)
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
