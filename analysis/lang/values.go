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

package lang

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// A ValueOp contains the methods necessary to implement an exhaustive switch on ssa.Value
type ValueOp interface {
	DoFunction(*ssa.Function)
	DoFreeVar(*ssa.FreeVar)
	DoParameter(*ssa.Parameter)
	DoConst(*ssa.Const)
	DoGlobal(*ssa.Global)
	DoBuiltin(*ssa.Builtin)
	DoAlloc(*ssa.Alloc)
	DoPhi(*ssa.Phi)
	DoCall(*ssa.Call)
	DoBinOp(*ssa.BinOp)
	DoUnOp(*ssa.UnOp)
	DoChangeType(*ssa.ChangeType)
	DoSliceToArrayPointer(*ssa.SliceToArrayPointer)
	DoMakeInterface(*ssa.MakeInterface)
	DoMakeClosure(*ssa.MakeClosure)
	DoMakeMap(*ssa.MakeMap)
	DoMakeChan(*ssa.MakeChan)
	DoMakeSlice(*ssa.MakeSlice)
	DoSlice(*ssa.Slice)
	DoFieldAddr(*ssa.FieldAddr)
	DoField(*ssa.Field)
	DoIndexAddr(*ssa.IndexAddr)
	DoIndex(*ssa.Index)
	DoLookup(*ssa.Lookup)
	DoSelect(*ssa.Select)
	DoRange(*ssa.Range)
	DoNext(*ssa.Next)
	DoTypeAssert(*ssa.TypeAssert)
	DoExtract(*ssa.Extract)
}

// ValueSwitch implements a simple switch on ssa.Value that applies the correct function from the ValueOp in each case.
//
//gocyclo:ignore
func ValueSwitch(vmap ValueOp, v *ssa.Value) {
	switch val := (*v).(type) {
	case *ssa.Function:
		vmap.DoFunction(val)
	case *ssa.FreeVar:
		vmap.DoFreeVar(val)
	case *ssa.Parameter:
		vmap.DoParameter(val)
	case *ssa.Const:
		vmap.DoConst(val)
	case *ssa.Global:
		vmap.DoGlobal(val)
	case *ssa.Builtin:
		vmap.DoBuiltin(val)
	case *ssa.Alloc:
		vmap.DoAlloc(val)
	case *ssa.Phi:
		vmap.DoPhi(val)
	case *ssa.Call:
		vmap.DoCall(val)
	case *ssa.BinOp:
		vmap.DoBinOp(val)
	case *ssa.UnOp:
		vmap.DoUnOp(val)
	case *ssa.ChangeType:
		vmap.DoChangeType(val)
	case *ssa.SliceToArrayPointer:
		vmap.DoSliceToArrayPointer(val)
	case *ssa.MakeInterface:
		vmap.DoMakeInterface(val)
	case *ssa.MakeClosure:
		vmap.DoMakeClosure(val)
	case *ssa.MakeMap:
		vmap.DoMakeMap(val)
	case *ssa.MakeChan:
		vmap.DoMakeChan(val)
	case *ssa.MakeSlice:
		vmap.DoMakeSlice(val)
	case *ssa.Slice:
		vmap.DoSlice(val)
	case *ssa.FieldAddr:
		vmap.DoFieldAddr(val)
	case *ssa.Field:
		vmap.DoField(val)
	case *ssa.IndexAddr:
		vmap.DoIndexAddr(val)
	case *ssa.Index:
		vmap.DoIndex(val)
	case *ssa.Lookup:
		vmap.DoLookup(val)
	case *ssa.Select:
		vmap.DoSelect(val)
	case *ssa.Range:
		vmap.DoRange(val)
	case *ssa.Next:
		vmap.DoNext(val)
	case *ssa.TypeAssert:
		vmap.DoTypeAssert(val)
	case *ssa.Extract:
		vmap.DoExtract(val)
	}
}

// ValuesWithSameData defines when values v1 and v2 refer to the same data.
// WARNING: This function is incomplete, and encodes only the necessary information for validators.
// You should modify as much as you need.
func ValuesWithSameData(v1 ssa.Value, v2 ssa.Value) bool {
	if v1 == v2 {
		return true
	}
	// v1 and v2 are loading the same pointer?
	if matchLoad(v1, v2) {
		return true
	}
	// v2 loads a field of v1?
	if z := MatchLoadField(v2); z != nil {
		return ValuesWithSameData(v1, z)
	}
	// v2 is a tuple element of v1?
	if z := MatchExtract(v2); z != nil {
		return ValuesWithSameData(v1, z)
	}
	// one of the two is a conversion
	if matchConversion(v1, v2) {
		return true
	}
	return false
}

func matchLoad(v1 ssa.Value, v2 ssa.Value) bool {
	l1, ok1 := v1.(*ssa.UnOp)
	l2, ok2 := v2.(*ssa.UnOp)
	if ok1 && ok2 && l1.Op == l2.Op && l1.Op == token.MUL {
		return ValuesWithSameData(l1.X, l2.X)
	}
	return false
}

func matchConversion(v1 ssa.Value, v2 ssa.Value) bool {
	l1, ok1 := v1.(*ssa.MakeInterface)
	if ok1 {
		return ValuesWithSameData(l1.X, v2)
	}

	l2, ok2 := v2.(*ssa.MakeInterface)
	if ok2 {
		return ValuesWithSameData(v1, l2.X)
	}

	return false
}

// MatchLoadField matches instruction sequence:
// y = &z.Field
// x = *y
// and returns (z,true) if x is given as argument
func MatchLoadField(x ssa.Value) ssa.Value {
	if x == nil {
		return nil
	}
	loadInstr, ok := x.(*ssa.UnOp)
	if !ok || loadInstr.Op != token.MUL {
		return nil
	}
	field, ok := loadInstr.X.(*ssa.FieldAddr)
	if !ok {
		return nil
	}
	return field.X
}

// MatchExtract is a proxy for matching a *ssa.Extract. It returns a non-nil value if x is some tuple-extraction value
// i.e. if x is extract y #0 for some y, then y is returned, otherwise nil
func MatchExtract(x ssa.Value) ssa.Value {
	if v, ok := x.(*ssa.Extract); ok {
		return v.Tuple
	}
	return nil
}

// MatchNilCheck returns a non-nil ssa value if x is a nil check, i.e. an instruction of the form
// 'y == nil' or  'y != nil' for some y
//
// The returned ssa value is the value being checked against. The boolean is true if the check is a check of the
// form 'y == nil' and false if 'y != nil'
func MatchNilCheck(v ssa.Value) (ssa.Value, bool) {
	x, ok := v.(*ssa.BinOp)
	if !ok {
		return nil, false
	}
	if (x.Op == token.NEQ || x.Op == token.EQL) && IsErrorType(x.X.Type()) {
		if x.X.String() == "nil:error" {
			return x.Y, x.Op == token.EQL
		} else if x.Y.String() == "nil:error" {
			return x.X, x.Op == token.EQL
		} else {
			return nil, false
		}
	}
	return nil, false
}

// MatchNegation returns a non-nil ssa. value if x is the negation of some value y, in which case y is returned.
func MatchNegation(x ssa.Value) ssa.Value {
	v, ok := x.(*ssa.UnOp)
	if ok && v.Op == token.NOT {
		return v.X
	}
	return nil
}

// TryTupleIndexType extract the type of element i in tuple type, or returns the type if it's not a tuple type
func TryTupleIndexType(v types.Type, i int) types.Type {
	tupleType, ok := v.(*types.Tuple)
	if !ok {
		return v
	}
	return tupleType.At(i).Type()
}

// CanType checks some properties to ensure calling the Type() method on the value won't cause a sefgfault.
// This seems to be a problem in the SSA.
func CanType(v ssa.Value) (res bool) {
	defer func() {
		if r := recover(); r != nil {
			res = false
		}
	}()
	if v == nil {
		res = false
	} else {
		typ := v.Type()
		res = typ != nil
	}
	return res
}
