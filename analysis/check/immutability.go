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

package check

import (
	"context"
	"errors"
	"fmt"
	"go/types"

	"golang.org/x/tools/container/intsets"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// checkSummaryImmutability returns the must-not-flows that were unproven after performing the
// immutability analysis.
// The immutability analysis filters out all must-not-flows that do not modify their output value(s).
// If an output value is not modified (immutable), then it is impossible to have data flow to it.
func checkSummaryImmutability(ctx context.Context, s *State, mustNotFlows []flow) checkResult {
	var unproven []flow
	for _, fl := range mustNotFlows {
		mustNotFlow, err := mustNotFlowImmutability(ctx, s, fl)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// Analysis timed out: return all unproven must-not-flows computed so far.
				unproven = append(unproven, fl)
				break
			}
		}
		// NOTE Maybe we shouldn't bother checking the rest since the summary is unsound, but
		// including all the unproven must-not-flows makes it easier to test.
		if !mustNotFlow {
			unproven = append(unproven, fl)
		}
	}

	return newCheckResult(unproven, Immutability)
}

// mustNotFlowImmutability returns true if fl.to is not written to (modified) in any way.
// It is impossible to have a data flow to an immutable value.
//
// If fl.to is pointer-like, then it uses the pointer analysis to detect any writes to the
// value(s)'s underlying memory in the flow's function or any of its transitively-reachable callees.
//
// Otherwise, fl.to is a scalar and must be a return value (since the types analysis filters out all
// scalar parameter outputs).
// If all values returned from the summary's return node are constants, then the return node is
// immutable.
// There is no need to analyze any callees because the value is stack allocated and therefore cannot
// be modified outside of the function.
func mustNotFlowImmutability(ctx context.Context, s *State, fl flow) (bool, error) {
	vals := outputVals(fl)

	for _, val := range vals {
		if isPointerLike(val.Type()) {
			s.Logger.Tracef(
				"output value %v (%v) in must-not-flow %v is pointer-like\n", val, val.Type(), fl)
			writeInstr, ok, err := checkWritesPtr(ctx, s, val)
			if err != nil {
				return false, fmt.Errorf(
					"failed to check writes to pointer-like value %v: %w", val, err)
			}
			if ok {
				s.Logger.Debugf(
					"found modification of output pointer value %v: %v at %s\n",
					val, writeInstr, s.Program.Fset.Position(writeInstr.Pos()))
				return false, nil
			}
		} else {
			if _, ok := fl.to.(*dataflow.ReturnValNode); !ok {
				panic(fmt.Errorf("detected scalar output in must-not-flow %v that is not a return", fl))
			}

			if !isPointerLike(val.Type()) && !lang.IsStaticallyDefinedLocal(val) {
				s.Logger.Debugf(
					"found non-static output scalar value %v in function %v",
					val, val.Parent())
				return false, nil
			}
		}
	}

	return true, nil
}

// checkWritesPtr returns the first instruction that writes a scalar value to to's underlying memory.
// If it returns false, there are no writes.
//
// It is an inter-procedural analysis which checks for writes in the value's enclosing function and
// its callees in BFS order.
func checkWritesPtr(ctx context.Context, s *State, to ssa.Value) (ptrWrite, bool, error) {
	cg := s.PointerAnalysis.CallGraph
	queue := []*callgraph.Node{cg.Nodes[to.Parent()]}
	seen := make(map[*callgraph.Node]struct{})
	seenFunc := make(map[*ssa.Function]struct{})

	ids := nodeIds(s.cache, to)
	for len(queue) > 0 {
		// This function can take a while so handle timeouts
		select {
		case <-ctx.Done():
			return ptrWrite{}, false, ctx.Err()
		default:
		}

		node := queue[0]
		queue = queue[1:]
		if _, ok := seen[node]; ok {
			continue
		}
		if node.Func == nil {
			return ptrWrite{}, false, nil
		}

		var writeInstr ptrWrite
		wrote := false
		// A function may be visited multiple times in different calling contexts so only analyze
		// each function once.
		if _, ok := seenFunc[node.Func]; !ok {
			// s.Logger.Tracef("checking for pointer writes in function %s\n", node.Func)
			lang.IterateInstructions(node.Func, func(_ int, instr ssa.Instruction) {
				write, ok := ptrWrittenTo(instr)
				if !ok {
					return
				}

				// // ASSUMPTION: We assume that errors are only used as values
				// if isAllocatedErrorType(write.Target) {
				// 	return
				// }

				mobjs := s.cache.Objects(write.Target)
				// If the target does not point to any memory, it is probably a nil-like local value
				// (e.g., empty slice), so any explicit stores to it counts as writing data.
				if len(mobjs) == 0 {
					wrote = true
					writeInstr = write
					return
				}
				// If the target's objects have any node ids as the output value, then the write
				// instruction writes data to the output value's memory.
				for mobj := range mobjs {
					if ids.Has(int(mobj.NodeID())) {
						wrote = true
						writeInstr = write
						return
					}
				}
			})
			seenFunc[node.Func] = struct{}{}
		}

		if wrote {
			return writeInstr, true, nil
		}

		for _, edge := range node.Out {
			queue = append(queue, edge.Callee)
		}
		seen[node] = struct{}{}
	}

	return ptrWrite{}, false, nil
}

// outputVals returns all of the SSA values that the flow's "to" node may refer to.
//
// If the "to" node is a return, then it includes the value returned at the given index for each
// return instruction in the function.
func outputVals(fl flow) []ssa.Value {
	var vals []ssa.Value
	switch to := fl.to.(type) {
	// TODO handle globals
	case *dataflow.ParamNode:
		vals = append(vals, to.SsaNode())
	case *dataflow.ReturnValNode:
		g := to.Graph()
		for retInstr := range g.Returns {
			retInstr, ok := retInstr.(*ssa.Return)
			if !ok {
				panic(fmt.Errorf("invalid return instruction %v", retInstr))
			}
			val := retInstr.Results[to.Index()]
			vals = append(vals, val)
		}
	}

	return vals
}

func nodeIds(c *aliasCache, val ssa.Value) *intsets.Sparse {
	ids := &intsets.Sparse{}
	objs := c.Objects(val)
	// initialize points-to-set of entrypoint
	for obj := range objs {
		switch data := obj.Data().(type) {
		case *ssa.MakeInterface:
			dataObjs := c.Objects(data.X) // get the objects of the concrete struct
			for obj := range dataObjs {
				for _, id := range obj.NodeIDs() {
					ids.Insert(int(id))
				}
			}
		default:
			for _, id := range obj.NodeIDs() {
				ids.Insert(int(id))
			}
		}
	}

	return ids
}

func isAllocatedErrorType(val ssa.Value) bool {
	// catch cases like: change interface any <- error (err)
	if ci, ok := val.(*ssa.ChangeInterface); ok {
		val = ci.X
	}

	typ := val.Type()
	switch t := typ.(type) {
	case *types.Pointer:
		typ = t.Elem().Underlying()
	case *types.Interface:
		typ = t.Underlying()
	}

	return types.AssignableTo(typ, types.Universe.Lookup("error").Type())
}

// aliasCache is a cache for transitive pointers and aliases.
type aliasCache struct {
	ptrRes         *pointer.Result
	objectPointees map[ssa.Value]map[*pointer.Object]struct{}
}

// Objects returns all the unique Objects that val points to.
// It caches the result for efficiency.
func (ac *aliasCache) Objects(val ssa.Value) map[*pointer.Object]struct{} {
	if mi, ok := val.(*ssa.MakeInterface); ok {
		// if val is an interface, the object is the concrete struct
		val = mi.X
	}
	if res, ok := ac.objectPointees[val]; ok && len(res) > 0 {
		return res
	}

	ptrs := findAllPointers(ac.ptrRes, val)
	if len(ptrs) == 0 {
		return nil
	}

	res := make(map[*pointer.Object]struct{}, len(ptrs))
	for _, ptr := range ptrs {
		for _, label := range ptr.PointsTo().Labels() {
			obj := label.Obj()
			if obj == nil {
				continue
			}

			// // ASSUMPTION: Skip allocated context.Context and error objects since we assume that
			// // they are used as values
			// switch data := obj.Data().(type) {
			// case *ssa.Alloc:
			// 	switch data.Type().String() {
			// 	case "*error", "*context.Context":
			// 		continue
			// 	}
			// }

			res[obj] = struct{}{}
		}
	}

	ac.objectPointees[val] = res
	return res
}

// findAllPointers returns all the pointers that point to v.
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

// isPointerLike returns true if typ or any of its sub-types (e.g., struct fields) can point.
func isPointerLike(t types.Type) bool {
	// Structs and arrays are stack-allocated so check their field/element type(s)
	switch t := t.(type) {
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			f := t.Field(i)
			if isPointerLike(f.Type()) {
				return true
			}
		}
	case *types.Array:
		return isPointerLike(t.Elem())
	}

	return canPoint(t)
}

// ptrWrite is an instruction that writes to an entrypoint's underlying memory.
type ptrWrite struct {
	ssa.Instruction
	Target ssa.Value // Target is the value written to.
	Value  ssa.Value // Value is the value that is written.
}

func (w ptrWrite) String() string {
	return fmt.Sprintf("write to %v with %v in %s", w.Target, w.Value, w.Instruction.Parent())
}

// ptrWrittenTo returns true if instruction writes a scalar value to a pointer
// value.
func ptrWrittenTo(instr ssa.Instruction) (ptrWrite, bool) {
	var lval ssa.Value
	var rval ssa.Value
	switch instr := instr.(type) {
	case *ssa.Store:
		lval = instr.Addr
		rval = instr.Val
	case *ssa.MapUpdate:
		lval = instr.Map
		rval = instr.Value
	case *ssa.Send:
		lval = instr.Chan
		rval = instr.X
	default:
		return ptrWrite{}, false
	}

	if instr.Parent() == nil {
		return ptrWrite{}, false
	}

	// // ASSUMPTION: we assume that errors are never used as pointer values
	// pkg := instr.Parent().Pkg
	// if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "errors" {
	// 	return ptrWrite{}, false
	// }

	if isPointerLike(lval.Type()) && isData(rval.Type()) {
		return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" && !canPoint(rval.Type()) {
				return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
			}
		}
	}

	return ptrWrite{}, false
}

// canPoint reports whether the type T is pointerlike, for the purposes of this analysis.
func canPoint(t types.Type) bool {
	switch t := t.(type) {
	case *types.Alias:
		return canPoint(t.Underlying())
	case *types.Named:
		if obj := t.Obj(); obj.Name() == "Value" && obj.Pkg().Path() == "reflect" {
			return true // treat reflect.Value like interface{}
		}
		return canPoint(t.Underlying())
	case *types.Pointer, *types.Interface, *types.Map, *types.Chan, *types.Signature, *types.Slice:
		return true
	case *types.Array, *types.Struct, *types.Tuple, *types.Basic:
		return false
	default:
		panic(fmt.Errorf("unhandled type: %v", t))
	}
}

func isData(t types.Type) bool {
	switch t := t.(type) {
	case *types.Alias:
		return isData(t.Underlying())
	case *types.Named:
		if obj := t.Obj(); obj.Name() == "Value" && obj.Pkg().Path() == "reflect" {
			return true // treat reflect.Value as data
		}
		return isData(t.Underlying())
	case *types.Basic, *types.Array, *types.Slice, *types.Map:
		return true
	default:
		return false
	}
}
