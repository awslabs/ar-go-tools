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
	"strings"

	"golang.org/x/tools/container/intsets"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// filterFlowsImmutability returns the flows that were unproven after performing the immutability
// analysis.
// The immutability analysis filters out all flows that do not modify their output value(s).
// If an output value is not modified (immutable), then it is impossible to have data flow to it.
func filterFlowsImmutability(ctx context.Context, s *State, flows []flow) []flow {
	var unproven []flow
	for _, fl := range flows {
		mustNotFlow, err := mustNotFlowImmutability(ctx, s, fl)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// Analysis timed out: return all unproven flows computed so far.
				unproven = append(unproven, fl)
				break
			}
		}
		// NOTE Maybe we shouldn't bother checking the rest since the summary is unsound, but
		// including all the unproven flows makes it easier to test.
		if !mustNotFlow {
			unproven = append(unproven, fl)
		}
	}

	return unproven
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
// immutable, so the function returns true.
// There is no need to analyze any callees because the return value is stack allocated and therefore
// cannot be modified outside of the function.
func mustNotFlowImmutability(ctx context.Context, s *State, fl flow) (bool, error) {
	vals := outputVals(fl)
	if _, ok := fl.to.node.(*dataflow.ReturnValNode); ok {
		for _, val := range vals {
			if !lang.IsStaticallyDefinedLocal(val) {
				s.Logger.Tracef(
					"found non-static return scalar value %v in function %v",
					val, val.Parent())
				return false, nil
			}
		}

		return true, nil
	}

	if len(vals) > 1 {
		panic(fmt.Errorf("multiple values for non-return flow output: %v", fl.to))
	}
	val := vals[0]
	if isPointerLike(val.Type()) {
		s.Logger.Tracef(
			"output value %v (%v) in must-not-flow %v is pointer-like\n", val, val.Type(), fl)
		writeInstr, ok, err := checkWritesPtrWithPath(ctx, s, val, fl.to)
		if err != nil {
			return false, fmt.Errorf(
				"failed to check writes to pointer-like value %v: %w", val, err)
		}
		if ok {
			s.Logger.Debugf(
				"found modification of output pointer value %v in must-not-flow %v: write %v at %s\n",
				val, fl, writeInstr, s.Program.Fset.Position(writeInstr.Pos()))
			return false, nil
		}
	}

	return true, nil
}

// checkWritesPtr returns an instruction that writes anything to to's underlying memory.
// If it returns false, there are no writes.
//
// It is an inter-procedural analysis which checks for writes in the value's enclosing function and
// its callees in BFS order.
func checkWritesPtr(ctx context.Context, s *State, to ssa.Value) (ptrWrite, bool, error) {
	return checkWritesPtrWithPath(ctx, s, to, graphNode{})
}

func checkWritesPtrWithPath(ctx context.Context, s *State, to ssa.Value, gn graphNode) (ptrWrite, bool, error) {
	cg := s.PointerAnalysis.CallGraph
	queue := []*callgraph.Node{cg.Nodes[to.Parent()]}
	seen := make(map[*callgraph.Node]struct{})
	seenFunc := make(map[*ssa.Function]struct{})

	ids := nodeIdsWithPath(s.cache, to, gn)
	s.Logger.Tracef("node ids of flow output value %v (%v) with path: %v\n", to, to.Type(), ids)
	if ids.Len() == 0 {
		// If there are no node ids, then the pointee does not represent any object(s) allocated on
		// the heap, which means it is impossible to write to it.
		return ptrWrite{}, false, nil
	}

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
		seen[node] = struct{}{}
		if node.Func == nil {
			return ptrWrite{}, false, nil
		}

		var writeInstr ptrWrite
		wrote := false
		// A function may be visited multiple times in different calling contexts so only analyze
		// each function once.
		if _, ok := seenFunc[node.Func]; ok {
			continue
		}
		seenFunc[node.Func] = struct{}{}

		s.Logger.Tracef(
			"checking for writes to memory of %v (%v) in function %s\n",
			to, to.Type(), node.Func)

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
			// If the target's objects have any of the same node ids as the output value, then
			// the write instruction writes a value to the output value's memory, and the output
			// value is not immutable.
			for mobj := range mobjs {
				if ids.Has(int(mobj.NodeID())) {
					if dataVal, ok := mobj.Data().(ssa.Value); ok {
						s.Logger.Tracef(
							"found write to val %v data: val node ids: %v, write target: %v, object: %v "+
								"(SSA name: %v)\n",
							to, ids, write.Target, mobj, dataVal.Name())
					} else {
						s.Logger.Tracef(
							"found write to val %v data: val node ids: %v, write target: %v, object: %v\n",
							to, ids, write.Target, mobj)
					}
					wrote = true
					writeInstr = write
					return
				}
			}
		})

		if wrote {
			return writeInstr, true, nil
		}

		for _, edge := range node.Out {
			queue = append(queue, edge.Callee)
		}
	}

	return ptrWrite{}, false, nil
}

// outputVals returns all of the SSA values that the flow's "to" node may refer to.
//
// If the "to" node is a return, then it includes the value returned at the given index for each
// return instruction in the function.
func outputVals(fl flow) []ssa.Value {
	var vals []ssa.Value
	switch to := fl.to.node.(type) {
	// TODO handle globals
	case *dataflow.ParamNode:
		vals = append(vals, to.SsaNode())
	case *dataflow.ReturnValNode:
		g := to.Graph()
		for retInstr := range g.Returns {
			retInstr, ok := retInstr.(*ssa.Return)
			if !ok {
				continue
			}
			val := retInstr.Results[to.Index()]
			vals = append(vals, val)
		}
	case *dataflow.FreeVarNode:
		vals = append(vals, to.SsaNode())
	default:
		panic(fmt.Errorf("unhandled flow output node type: %T", fl.to))
	}

	return vals
}

func nodeIds(c *aliasCache, val ssa.Value) *intsets.Sparse {
	return nodeIdsWithPath(c, val, graphNode{})
}

func nodeIdsWithPath(c *aliasCache, val ssa.Value, gn graphNode) *intsets.Sparse {
	ids := &intsets.Sparse{}
	objs := c.ObjectsWithPath(val, gn)
	// initialize points-to-set of entrypoint
	for obj := range objs {
		switch data := obj.Data().(type) {
		case *ssa.MakeInterface:
			dataObjs := c.ObjectsWithPath(data.X, gn)
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

// aliasCache is a cache for transitive pointers and aliases.
type aliasCache struct {
	ptrRes         *pointer.Result
	objectPointees map[ssa.Value]map[*pointer.Object]struct{}
	pathPointees   map[string]map[*pointer.Object]struct{}
}

// Objects returns all the unique Objects that val points to.
// It caches the result for efficiency.
func (ac *aliasCache) Objects(val ssa.Value) map[*pointer.Object]struct{} {
	return ac.ObjectsWithPath(val, graphNode{})
}

// ObjectsWithPath returns all the unique Objects that val points to, filtered by field path.
func (ac *aliasCache) ObjectsWithPath(val ssa.Value, gn graphNode) map[*pointer.Object]struct{} {
	if mi, ok := val.(*ssa.MakeInterface); ok {
		// If val is an interface, the object is the concrete struct.
		val = mi.X
	}
	
	// Build cache key
	cacheKey := val.String()
	if gn.pathLen() > 0 {
		cacheKey += gn.pathStr()
	}
	
	if res, ok := ac.pathPointees[cacheKey]; ok && len(res) > 0 {
		return res
	}

	ptrs := findAllPointers(ac.ptrRes, val)
	if len(ptrs) == 0 {
		return nil
	}

	// Get target path for filtering
	targetPath := gn.pathStr()

	res := make(map[*pointer.Object]struct{}, len(ptrs))
	for _, ptr := range ptrs {
		for _, label := range ptr.PointsTo().Labels() {
			obj := label.Obj()
			if obj == nil {
				continue
			}

			// If we're looking for a specific path, filter by it
			if gn.pathLen() > 0 {
				labelPath := label.Path()
				// Match exact path or paths that start with our target
				if labelPath != targetPath && !strings.HasPrefix(labelPath, targetPath+".") {
					continue
				}
			}

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

// canPoint returns true if the type t is pointer-like.
//
// We define pointer-like as a type whose underlying Go representation is a pointer.
func canPoint(t types.Type) bool {
	switch t := t.(type) {
	case *types.Alias:
		return canPoint(t.Underlying())
	case *types.Named:
		return canPoint(t.Underlying())
	case *types.Pointer, *types.Interface, *types.Map, *types.Chan, *types.Signature, *types.Slice:
		return true
	case *types.Array, *types.Struct, *types.Tuple, *types.Basic:
		return false
	default:
		panic(fmt.Errorf("unhandled type: %v", t))
	}
}

// ptrWrite is an instruction that writes to an entrypoint's underlying memory.
type ptrWrite struct {
	ssa.Instruction
	Target ssa.Value // Target is the value written to.
	Value  ssa.Value // Value is the value that is written.
}

func (w ptrWrite) String() string {
	return fmt.Sprintf("to %v with %v in %s", w.Target, w.Value, w.Instruction.Parent())
}

// ptrWrittenTo returns true if instruction writes a value (r-value) to a pointer-like value
// (l-value) in a write operation (store, map update, or channel send instruction).
//
// NOTE SSA store operations only store values to pointers. So a store to an integer will look like:
//
//	t0 = new int
//	t1 = &t0
//	*t1 = 1 <- the l-value ssa.Value is a pointer here
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

	if isPointerLike(lval.Type()) {
		return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" {
				return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
			}
		}
	}

	return ptrWrite{}, false
}
