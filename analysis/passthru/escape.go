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

package passthru

import (
	"fmt"
	"go/token"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

type EscapedCoreAlloc struct {
	AccessedCoreAlloc
	Escapes []Escape
}

// Escape is a value that results in a AccessedCoreAlloc heap permission
// "escaping" a function.
type Escape struct {
	ssa.Value
	Pos token.Position
	Ctx EscapeContext
}

func (e Escape) String() string {
	return fmt.Sprintf("escape (%v) via value %v in %v at %v", e.Ctx, e.Value, e.Parent().Name(), e.Pos)
}

type EscapeContext int

const (
	Write = iota + 1
	FreeVar
	Arg
	Return
)

func (e EscapeContext) String() string {
	switch e {
	case Write:
		return "write"
	case FreeVar:
		return "free var"
	case Arg:
		return "arg"
	case Return:
		return "return"
	default:
		panic(fmt.Errorf("invalid escape context: %v", int(e)))
	}
}

// findEscapes modifies escapes by adding the values whose permissions are a
// subset of alloc's permissions, and "escape" the function f.
//
// We only perform this analysis on functions in the Core. For any functions
// called within the Core that are not part of the Core package (e.g., standard
// library, dependencies), we assume that all allocations in these functions do
// not escape.
//
//gocyclo:ignore
func findEscapes(state *state, f *ssa.Function, alloc AccessedCoreAlloc) []Escape {
	var res []Escape
	cache := state.cache
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		pos := state.fset.Position(instr.Pos())
		switch instr := instr.(type) {
		case *ssa.Store, *ssa.MapUpdate, *ssa.Send:
			if write, ok := ptr.PtrWrittenToPtr(instr, pos); ok {
				if alloc, ok := write.Value.(*ssa.Alloc); ok && !alloc.Heap {
					break
				}

				if hasPermissionsOf(cache, write.Target, alloc.Value) {
					// if !isValAllocatedOutside(state, write.Target, write.Parent()) {
					// 	state.logger.Debugf("Skipping analyzing for escapes: %v target allocated inside %v\n", write, write.Parent())
					// 	break
					// }

					// if pos.Line == alloc.Pos.Line {
					// 	break
					// }

					esc := Escape{
						Value: write.Target,
						Pos:   write.Pos,
						Ctx:   Write,
					}
					res = append(res, esc)
				}
			}
		case *ssa.MakeClosure:
			for _, freeVar := range instr.Bindings {
				if hasPermissionsOf(cache, freeVar, alloc.Value) {
					if !pos.IsValid() {
						pos = state.fset.Position(freeVar.Pos())
					}
					esc := Escape{
						Value: freeVar,
						Pos:   pos,
						Ctx:   FreeVar,
					}
					res = append(res, esc)
				}
			}
		case ssa.CallInstruction:
			if callDoesNotLeakArgs(instr.Common()) {
				break
			}

			args := lang.GetArgs(instr)
			var escapingArgs []ssa.Value
			for _, arg := range args {
				if hasPermissionsOf(cache, arg, alloc.Value) {
					escapingArgs = append(escapingArgs, arg)
				}
			}

			// args are fine if we analyze all transitive callees
			if len(escapingArgs) > 0 {
				escs, ok := escapesInCallees(state, instr, alloc)
				if !ok {
					break
				}

				if len(escs) > 0 {
					res = append(res, escs...)
				} else {
					// if no concrete escapes were found, assume the arguments escape
					for _, arg := range escapingArgs {
						esc := Escape{
							Value: arg,
							Pos:   pos,
							Ctx:   Arg,
						}
						res = append(res, esc)
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
func hasPermissionsOf(cache *ptr.AliasCache, val ssa.Value, allocVal ssa.Value) bool {
	if val.Parent() == nil {
		return false
	}

	valObjs := cache.Objects(val)
	allocObjs := cache.Objects(allocVal)
	for valObj := range valObjs {
		for allocObj := range allocObjs {
			if valObj.NodeID() != allocObj.NodeID() {
				return false
			}
		}
	}

	return true
}

// escapesInCallees returns the first escaped values found in any of call's
// transitive callees. Returns the escapes and true if any were found.
func escapesInCallees(state *state, call ssa.CallInstruction, alloc AccessedCoreAlloc) ([]Escape, bool) {
	if callDoesNotLeakArgs(call.Common()) {
		return nil, false
	}

	f := call.Common().StaticCallee()
	if f == nil {
		// TODO
		panic(fmt.Errorf("non-static callees not handled yet: %v in %v", call.Common(), call.Parent()))
	}

	// run BFS to converge faster
	cg := state.cache.PtrState.PointerAnalysis.CallGraph
	node, ok := cg.Nodes[f]
	if !ok {
		return nil, true
	}
	que := []*callgraph.Node{node}
	seen := make(map[*callgraph.Node]bool)
	for len(que) != 0 {
		cur := que[0]
		que = que[1:]

		if seen[cur] {
			continue
		}

		if funcDoesNotLeakArgs(cur.Func) {
			seen[cur] = true
			continue
		}

		escs := findEscapes(state, cur.Func, alloc)
		if len(escs) > 0 {
			return escs, true
		}
		seen[cur] = true
		for _, edge := range cur.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}

			que = append(que, edge.Callee)
		}
	}

	return nil, false
}

func callDoesNotLeakArgs(call *ssa.CallCommon) bool {
	if _, ok := call.Value.(*ssa.Builtin); ok {
		return true
	}
	if call.IsInvoke() {
		switch call.Method.Name() {
		case "String", "Error":
			return true
		default:
			return false
		}
	}

	return funcDoesNotLeakArgs(call.StaticCallee())
}

// funcDoesNotLeakArgs returns true if f does not leak any of its arguments.
// We assume that any function with a dataflow summary satisfies this property.
func funcDoesNotLeakArgs(f *ssa.Function) bool {
	_, hasSummary := summaries.SummaryOfFunc(f)
	return hasSummary
}

func isValAllocatedOutside(state *state, val ssa.Value, f *ssa.Function) bool {
	for _, cf := range state.funcs.core {
		if cf.f == f {
			continue
		}

		if isValAllocatedIn(state, val, cf.f) {
			return true
		}
	}

	for _, af := range state.funcs.app {
		if af == f {
			continue
		}

		if isValAllocatedIn(state, val, af) {
			return true
		}
	}

	return false
}

func isValAllocatedIn(state *state, val ssa.Value, f *ssa.Function) bool {
	found := false
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		if found {
			return
		}

		if allocatedVal, ok := isAllocInstr(instr); ok {
			if hasPermissionsOf(state.cache, val, allocatedVal) {
				found = true
				return
			}
		}
	})

	return found
}
