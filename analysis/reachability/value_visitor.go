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

package reachability

import (
	"golang.org/x/tools/go/ssa"
)

//gocyclo:ignore
func preTraversalVisitValuesInstruction(instruction ssa.Instruction, seen map[ssa.Value]bool, action func(ssa.Value)) {

	if instruction == nil {
		return
	}

	visit := func(v ssa.Value) {
		preTraversalVisitValues(v, seen, action)
	}

	switch x := instruction.(type) {

	case *ssa.BinOp:
		visit(x.X)
		visit(x.Y)

	case *ssa.Call:
		common := x.Common()
		if common == nil {
			return
		}

		visit(common.Value)

		for i := range common.Args {
			visit(common.Args[i])
		}

	case *ssa.ChangeInterface:
		visit(x.X)

	case *ssa.ChangeType:
		visit(x.X)

	case *ssa.Convert:
		//fmt.Println("visiting an Instruction Convert to ", x.X.Type())
		visit(x.X)

	case *ssa.DebugRef:
		visit(x.X)

	case *ssa.Defer:
		visit(x.Call.Value)

	case *ssa.Extract:
		visit(x.Tuple)

	case *ssa.Field:
		visit(x.X)

	case *ssa.FieldAddr:
		visit(x.X)

	case *ssa.Go:
		visit(x.Call.Value)

	case *ssa.If:
		visit(x.Cond)

	case *ssa.Index:
		visit(x.X)
		visit(x.Index)

	case *ssa.IndexAddr:
		visit(x.X)
		visit(x.Index)

	case *ssa.Lookup:
		visit(x.X)
		visit(x.Index)

	case *ssa.MakeChan:
		visit(x.Size)

	case *ssa.MakeClosure:
		visit(x.Fn)
		for i := range x.Bindings {
			visit(x.Bindings[i])
		}

	case *ssa.MakeInterface:
		visit(x.X)

	case *ssa.MakeMap:
		visit(x.Reserve)

	case *ssa.MakeSlice:
		visit(x.Len)
		visit(x.Cap)

	case *ssa.MapUpdate:
		visit(x.Map)
		visit(x.Key)
		visit(x.Value)

	case *ssa.Next:
		visit(x.Iter)

	case *ssa.Panic:
		visit(x.X)

	case *ssa.Phi:
		for _, edge := range x.Edges {
			visit(edge)
		}

	case *ssa.Range:
		visit(x.X)

	case *ssa.Return:
		for i := range x.Results {
			visit(x.Results[i])
		}

	case *ssa.Select:
		for _, state := range x.States {
			visit(state.Chan)
			visit(state.Send)
		}

	case *ssa.Send:
		visit(x.Chan)
		visit(x.X)

	case *ssa.Slice:
		for _, val := range []ssa.Value{x.X, x.Low, x.High, x.Max} {
			visit(val)
		}

	case *ssa.Store:
		visit(x.Addr)
		visit(x.Val)

	case *ssa.TypeAssert:
		visit(x.X)

	case *ssa.UnOp:
		visit(x.X)
	}
}

//gocyclo:ignore
func preTraversalVisitValues(value ssa.Value, seen map[ssa.Value]bool, action func(ssa.Value)) {

	if value == nil || seen[value] {
		return
	}

	// perform the action on the node
	action(value)

	seen[value] = true

	// visit the children
	visit := func(v ssa.Value) {
		preTraversalVisitValues(v, seen, action)
	}

	switch x := value.(type) {

	case *ssa.BinOp:
		visit(x.X)
		visit(x.Y)

	case *ssa.Call:
		common := x.Common()
		if common == nil {
			return
		}
		visit(common.Value)
		for i := range common.Args {
			visit(common.Args[i])
		}

	case *ssa.ChangeInterface:
		visit(x.X)

	case *ssa.ChangeType:
		visit(x.X)

	case *ssa.Convert:
		visit(x.X)

	case *ssa.Extract:
		visit(x.Tuple)

	case *ssa.Field:
		visit(x.X)

	case *ssa.FieldAddr:
		visit(x.X)

	case *ssa.Function:
		for i := range x.Params {
			visit(x.Params[i])
		}
		for i := range x.FreeVars {
			visit(x.FreeVars[i])
		}
		for i := range x.Locals {
			visit(x.Locals[i])
		}
		for i := range x.AnonFuncs {
			visit(x.AnonFuncs[i])
		}

	case *ssa.Index:
		visit(x.X)
		visit(x.Index)

	case *ssa.IndexAddr:
		visit(x.X)
		visit(x.Index)

	case *ssa.Lookup:
		visit(x.X)
		visit(x.Index)

	case *ssa.MakeChan:
		visit(x.Size)

	case *ssa.MakeClosure:
		visit(x.Fn)
		for i := range x.Bindings {
			visit(x.Bindings[i])
		}

	case *ssa.MakeInterface:
		visit(x.X)

	case *ssa.MakeMap:
		visit(x.Reserve)

	case *ssa.MakeSlice:
		visit(x.Len)
		visit(x.Cap)

	case *ssa.Next:
		visit(x.Iter)

	case *ssa.Phi:
		for _, edge := range x.Edges {
			visit(edge)
		}

	case *ssa.Range:
		visit(x.X)

	case *ssa.Select:
		for _, state := range x.States {
			visit(state.Chan)
			visit(state.Send)
		}

	case *ssa.Slice:
		visit(x.X)
		visit(x.Low)
		visit(x.High)
		visit(x.Max)

	case *ssa.TypeAssert:
		visit(x.X)

	case *ssa.UnOp:
		visit(x.X)
	}
}
