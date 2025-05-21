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
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/exp/maps"
	"golang.org/x/tools/go/ssa"
)

// EscapedCoreAlloc is a value allocated in the Core and accessed in the App
// that has "escaped" the Core.
type EscapedCoreAlloc struct {
	AccessedCoreAlloc
	Escapes []Escape
}

// Escape is a value that has "escaped" a function.
//
// A value "escapes" a function by getting allocated on the heap and there
// existing any value in the program other than the desired argument or return
// value having separation logic permissions to access the allocated value.
type Escape struct {
	ssa.Value
	Pos token.Position
	Ctx EscapeContext
}

func (e Escape) String() string {
	const debug = false
	if debug {
		return fmt.Sprintf("escape (%v) via value %v (%T of type %v (%T)) in %v at %v",
			e.Ctx, e.Value, e.Value, e.Value.Type(), e.Value.Type(), e.Parent().String(), e.Pos)
	}

	return fmt.Sprintf("escape (%v) via value %v (type %v) in %v at %v",
		e.Ctx, e.Value, e.Value.Type(), e.Parent().String(), e.Pos)
}

// EscapeContext indicates how a value "escaped" a function.
type EscapeContext int

const (
	// Write is any write to memory that results in an escape.
	Write = iota + 1
	// FreeVar is any value captured by a closure that results in an escape.
	FreeVar
	// Arg is a value passed to a function that results in an escape.
	Arg
)

func (e EscapeContext) String() string {
	switch e {
	case Write:
		return "write"
	case FreeVar:
		return "free var"
	case Arg:
		return "arg"
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

	// Run BFS to converge faster
	// May have to analyze functions inter-procedurally which is why this is BFS instead of recursion
	que := []*ssa.Function{f}
	seen := make(map[*ssa.Function]bool)
	for len(que) != 0 {
		cur := que[0]
		que = que[1:]

		if seen[cur] {
			continue
		}
		seen[cur] = true

		if funcDoesNotLeak(state.spec, funcWithCtx{f: cur, ctx: unknown}) {
			state.logger.Debugf(
				"\t\tskipping escape check because Core function does not leak args: %v\n", cur)
			continue
		}

		state.logger.Debugf("checking escapes in function: %v\n", cur)

		lang.IterateInstructions(cur, func(_ int, instr ssa.Instruction) {
			pos := state.fset.Position(instr.Pos())
			if state.df.Annotations.IsIgnoredPos(pos, state.spec.Tag) {
				return
			}

			switch instr := instr.(type) {
			case *ssa.Store, *ssa.MapUpdate, *ssa.Send:
				if write, ok := ptr.PtrWrittenToPtr(instr, pos); ok {
					// value escapes if it is written to any heap location
					if alloc, ok := write.Value.(*ssa.Alloc); ok && !alloc.Heap {
						break
					}

					if hasPermissionsOf(cache, write.Value, alloc.Value) {
						esc := Escape{
							Value: write.Value,
							Pos:   pos,
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
							if state.df.Annotations.IsIgnoredPos(pos, state.spec.Tag) {
								return
							}
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
				if callDoesNotLeak(instr.Common()) {
					break
				}

				state.logger.Debugf("call in Core may leak args: %v with signature: %v\n", instr, instr.Common().Signature())
				args := lang.GetArgs(instr)
				var escapingArgs []ssa.Value
				for _, arg := range args {
					if hasPermissionsOf(cache, arg, alloc.Value) {
						escapingArgs = append(escapingArgs, arg)
					}
				}

				if len(escapingArgs) > 0 {
					possibleCallees, err := state.df.ResolveCallee(instr, true)
					if err != nil {
						// If there are no possible callees found, assume that the
						// called function cannot leak via arguments
						state.logger.Warnf("no callees found for %v at %v\n", instr, pos)
						break
					}

					// Analyze the callee (or multiple if invoked method call) for escapes
					que = append(que, maps.Keys(possibleCallees)...)
				}
			}
		})
	}

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

// callDoesNotLeak returns true if call cannot leak internal allocations via
// any of its arguments.
//
// A function cannot leak permissions to internal allocations via an argument if
// the argument is a "shallow" (scalar or pointer to a scalar) type.
//
// We assume that any function with a dataflow summary satisfies this property.
func callDoesNotLeak(call *ssa.CallCommon) bool {
	if _, ok := call.Value.(*ssa.Builtin); ok {
		return true
	}

	allShallow := true
	params := call.Signature().Params()
	for i := 0; i < params.Len(); i++ {
		paramType := params.At(i)
		if !isShallowPtrType(paramType.Type()) {
			allShallow = false
			break
		}
	}
	if allShallow {
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

	return false
}

// funcDoesNotLeak returns true if f does not leak internal allocations.
func funcDoesNotLeak(spec config.DiodonPassThroughSpec, cf funcWithCtx) bool {
	// Functions in the App cannot leak
	// if cf.ctx == app {
	// 	return true
	// }

	for _, cid := range spec.NoLeakFunctions {
		if cid.MatchPackageAndMethod(cf.f) {
			return true
		}
	}

	return summaries.IsStdFunction(cf.f)
}

func isShallowPtrType(typ types.Type) bool {
	switch typ := typ.(type) {
	case *types.Signature:
		// closure can leak internal function data
		return false
	case *types.Pointer:
		return !pointer.CanPoint(typ.Elem())
	case *types.Slice:
		return !pointer.CanPoint(typ.Elem())
	case *types.Map:
		return !pointer.CanPoint(typ.Key()) && !pointer.CanPoint(typ.Elem())
	case *types.Chan:
		return !pointer.CanPoint(typ.Elem())
	case *types.Named:
		return isShallowPtrType(typ.Underlying())
	}

	return true
}
