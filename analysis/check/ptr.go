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
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/internal/pointer"
)

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

			// ASSUMPTION: Skip allocated context.Context and error objects since we assume that
			// they are used as values
			switch data := obj.Data().(type) {
			case *ssa.Alloc:
				switch data.Type().String() {
				case "*error", "*context.Context":
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

	return pointer.CanPoint(t)
}

func reachableFrom(cg *callgraph.Graph, start *ssa.Function) []*ssa.Function {
	queue := []*callgraph.Node{cg.Nodes[start]}
	seen := make(map[*callgraph.Node]struct{})
	var reach []*ssa.Function

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if _, ok := seen[node]; ok {
			continue
		}
		for _, edge := range node.Out {
			queue = append(queue, edge.Callee)
		}
		seen[node] = struct{}{}
	}

	return reach
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

// ptrRead is an instruction that reads from an entrypoint's underlying memory.
type ptrRead struct {
	ssa.Instruction
	Values []ssa.Value // Values are the values that are read from.
}

func (r ptrRead) String() string {
	return fmt.Sprintf("read of %v in %s", r.Values, r.Instruction.Parent())
}

// ptrWrittenTo returns true if instruction writes a scalar value to a pointer
// value.
func ptrWrittenTo(instr ssa.Instruction, pos token.Position) (ptrWrite, bool) {
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
	pkg := instr.Parent().Pkg
	// we assume that errors are never used as pointer values
	if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "errors" {
		return ptrWrite{}, false
	}

	if !pointer.CanPoint(rval.Type()) && pointer.CanPoint(lval.Type()) {
		return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" && !pointer.CanPoint(rval.Type()) {
				return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
			}
		}
	}

	return ptrWrite{}, false
}

// ptrWrittenToPtr returns true if instruction writes a pointer value to a pointer
// value.
//
// TODO refactor to reduce duplication
//
//gocyclo:ignore
func ptrWrittenToPtr(instr ssa.Instruction) (ptrWrite, bool) {
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
	pkg := instr.Parent().Pkg
	// we assume that errors are never used as pointer values
	if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "errors" {
		return ptrWrite{}, false
	}

	if pointer.CanPoint(rval.Type()) && pointer.CanPoint(lval.Type()) {
		switch rval := rval.(type) {
		case *ssa.ChangeInterface:
			// Special case for: e.g. change interface interface{} <- error
			// we assume that errors are never used as pointer values
			if rval.X.Type().String() == "error" {
				return ptrWrite{}, false
			}
		case *ssa.Call:
			// Special case for: e.g. fmt.Errorf(...) where the return type is an error
			if rval.Type().String() == "error" {
				return ptrWrite{}, false
			}
		}

		return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" && pointer.CanPoint(rval.Type()) {
				return ptrWrite{Instruction: instr, Target: lval, Value: rval}, true
			}
		}
	}

	return ptrWrite{}, false
}

// ptrsReadFrom returns a read instruction containing all the pointer values
// read from instruction.
//
//gocyclo:ignore
func ptrsReadFrom(instr ssa.Instruction) (ptrRead, bool) {
	var rvals []ssa.Value
	add := func(vs ...ssa.Value) {
		for _, v := range vs {
			if v == nil {
				continue
			}

			if pointer.CanPoint(v.Type()) {
				rvals = append(rvals, v)
			}
		}
	}

	switch instr := instr.(type) {
	case *ssa.Call:
		if _, ok := instr.Call.Value.(*ssa.Builtin); ok {
			add(instr.Call.Args...)
		}
	case *ssa.Index:
		add(instr.X)
	case *ssa.Lookup:
		add(instr.X, instr.Index)
	case *ssa.Slice:
		add(instr.X)
	case *ssa.UnOp:
		// Dereference y = *x
		if instr.Op == token.MUL {
			add(instr.X)
		}
		// Channel receive y <- x
		if instr.Op == token.ARROW {
			add(instr.X)
		}
	}

	if len(rvals) == 0 {
		return ptrRead{Instruction: instr, Values: nil}, false
	}

	return ptrRead{Instruction: instr, Values: rvals}, true
}
