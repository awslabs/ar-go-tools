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

package modptr

import (
	"fmt"
	"go/types"
	"golang.org/x/tools/go/ssa/ssautil"
	"strconv"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	goPointer "golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// aliasCache represents a "global" cache for transitive pointers and aliases.
//
// The analysis only searches for pointers and aliases that are reachable from a
// single entrypoint, but this cache helps if there are multiple entrypoints
// that need alias information computed from previous entrypoints.
type aliasCache struct {
	prog   *ssa.Program
	ptrRes *pointer.Result
	// goPtrRes is needed for functions that only work with the x/tools pointer analysis types.
	goPtrRes       *goPointer.Result
	reachableFuncs map[*ssa.Function]bool
	objectPointees map[ssa.Value]map[*pointer.Object]struct{}
}

// findEntrypoints returns all the analysis entrypoints specified by spec.
func (ac *aliasCache) findEntrypoints(spec config.ModValSpec) map[Entrypoint]struct{} {
	entrypoints := make(map[Entrypoint]struct{})
	for fn, node := range ac.ptrRes.CallGraph.Nodes {
		if fn == nil {
			continue
		}
		if _, ok := ac.reachableFuncs[fn]; !ok {
			continue
		}

		for _, inEdge := range node.In {
			if inEdge == nil || inEdge.Site == nil {
				continue
			}

			entry, ok := ac.findEntrypoint(spec, inEdge.Site.Value())
			if !ok {
				continue
			}

			entrypoints[entry] = struct{}{}
		}
	}

	return entrypoints
}

func (ac *aliasCache) findEntrypoint(spec config.ModValSpec, call *ssa.Call) (Entrypoint, bool) {
	// use analysisutil entrypoint logic to take care of function aliases and
	// other edge-cases
	if !analysisutil.IsEntrypointNode(ac.goPtrRes, call, spec.IsValue) {
		return Entrypoint{}, false
	}

	callPos := ac.prog.Fset.Position(call.Pos())
	for _, cid := range spec.Values {
		// TODO parse label beforehand to prevent panics
		idx, err := strconv.Atoi(cid.Label)
		if err != nil {
			err := fmt.Errorf("cid label is not a valid argument index: %v", err)
			panic(err)
		}
		if idx < 0 {
			err := fmt.Errorf("cid label is not a valid argument index: %v < 0", idx)
			panic(err)
		}

		args := lang.GetArgs(call)
		if len(args) < idx {
			fmt.Printf("arg index: %v < want %v\n", len(args), idx)
			return Entrypoint{}, false
		}

		val := args[idx]
		if cid.Type != "" && !cid.MatchType(val.Type()) {
			continue
		}

		return Entrypoint{Val: val, Call: call, Pos: callPos}, true
	}

	return Entrypoint{}, false
}

// findAllPointers returns all the pointers that point to v.
//
// Copied from analysis/lang package.
func findAllPointers(res *pointer.Result, v ssa.Value) []pointer.Pointer {
	var allptr []pointer.Pointer
	if ptr, ptrExists := res.Queries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	// By indirect query
	if ptr, ptrExists := res.IndirectQueries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	return allptr
}

// DoPointerAnalysis is the same as dataflow.DoPointerAnalysis.
func DoPointerAnalysis(p *ssa.Program, functionFilter func(*ssa.Function) bool, buildCallGraph bool) (*pointer.Result,
	error) {
	pCfg := &pointer.Config{
		Mains:           ssautil.MainPackages(p.AllPackages()),
		Reflection:      false,
		BuildCallGraph:  buildCallGraph,
		Queries:         make(map[ssa.Value]struct{}),
		IndirectQueries: make(map[ssa.Value]struct{}),
	}

	for function := range ssautil.AllFunctions(p) {
		// If the function is a user-defined function (it can be from a dependency) then every Value that can
		// can potentially alias is marked for querying.
		if functionFilter(function) {
			// Add all function parameters
			for _, param := range function.Params {
				addValueQuery(pCfg, param)
			}
			// Add all free variables
			for _, fv := range function.FreeVars {
				addValueQuery(pCfg, fv)
			}

			lang.IterateInstructions(function, func(_ int, instruction ssa.Instruction) {
				addInstructionQuery(pCfg, instruction)
			})
		}
	}

	// Do the pointer analysis
	return pointer.Analyze(pCfg)
}

// addQuery adds a query for the instruction to the pointer configuration, performing all the necessary checks to
// ensure the query can be added safely.
func addInstructionQuery(cfg *pointer.Config, instruction ssa.Instruction) {
	if instruction == nil {
		return
	}
	// DebugRefs are ignored because they may cause spurious aliasing
	if _, isDebugRef := instruction.(*ssa.DebugRef); isDebugRef {
		return
	}

	for _, operand := range instruction.Operands([]*ssa.Value{}) {
		if *operand != nil && (*operand).Type() != nil {
			addValueQuery(cfg, *operand)
		}
	}
}

func addValueQuery(cfg *pointer.Config, value ssa.Value) {
	if value == nil {
		return
	}
	typ := value.Type()
	if pointer.CanPoint(typ) {
		cfg.AddQuery(value)
	}
	indirectQuery(cfg, typ, value)
}

// indirectQuery wraps an update to the IndirectQuery of the pointer config. We need to wrap it
// because typ.Underlying() may panic despite typ being non-nil
func indirectQuery(cfg *pointer.Config, typ types.Type, val ssa.Value) {
	defer func() {
		if r := recover(); r != nil {
			// Do nothing. Is that panic a bug? Occurs on a *ssa.opaqueType
		}
	}()

	if typ.Underlying() != nil {
		// Add indirect query if Value is of pointer type, and underlying type can point
		if ptrType, ok := typ.Underlying().(*types.Pointer); ok {
			if pointer.CanPoint(ptrType.Elem()) {
				cfg.AddIndirectQuery(val)
			}
		}
	}
}
