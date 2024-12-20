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

// CanType checks some properties to ensure calling the Type() method on the value won't cause a segfault.
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

// IsStaticallyDefinedLocal returns true if the value is statically defined, i.e. its value is entirely defined at
// compile time.
// This is the case for:
// - constants
// - slices of constants
// This does not analyze whether the value v is mutated; this function is useful in conjunction with the dataflow
// analyzes for example, which would track all dataflows to the values being analyzed. For values of nodes that do
// not have any other incoming edges, this function is sound: the dataflow analysis indirectly guarantees no data
// is flowing from a parameter of the function, or from being written to by another function being called in the
// function body.
//
// TODO: make this function usable outside of dataflow analysis
func IsStaticallyDefinedLocal(v ssa.Value) bool {
	if v == nil {
		return false
	}
	switch value := v.(type) {
	case *ssa.Const:
		return true
	case *ssa.Slice:
		// A slice is statically defined if the original slice is
		return IsStaticallyDefinedLocal(value.X)
	case *ssa.Alloc:
		// check that the allocation is static in a separate function
		return isStaticallyDefinedAlloc(value)
	case *ssa.MakeInterface:
		// make I <- <statically defined value> is statically define
		return IsStaticallyDefinedLocal(value.X)
	case *ssa.MakeSlice:
		// A make slice is statically defined if it is initialized with a statically defined length and all the elements
		// stored in it are statically defined
		return IsStaticallyDefinedLocal(value.Len)
	case *ssa.UnOp:
		// When have x = *y, x is statically defined if y is.
		if value.Op == token.MUL {
			return IsStaticallyDefinedLocal(value.X)
		}
		return false
	case *ssa.IndexAddr:
		// &A[I] is statically defined is A and I are (typically, recursive call will check that A was allocated in
		// the function, is an array and all stores to it are statically defined data.
		return IsStaticallyDefinedLocal(value.X) && IsStaticallyDefinedLocal(value.Index)
	default:
		// By default, consider it non-static
		return false
	}
}

// isStaticallyDefinedAlloc recognizes patterns of allocation that are static. Those are often generated during the SSA
// translation of static var allocations in the code, where slices must be constructed by adding all elements
// individually.
func isStaticallyDefinedAlloc(alloc *ssa.Alloc) bool {
	if ptrTy, isPtrTy := alloc.Type().(*types.Pointer); isPtrTy {
		switch ptrTy.Elem().(type) {
		case *types.Array:
			// Check all referrers that take references and then store data are storing static data
			for _, referrer := range *alloc.Referrers() {
				if isRefTakingReferrer(referrer) && !getsStaticData(referrer) {
					return false
				}
			}
			// All referrers have been checked
			return true
		default:
			return false
		}
	}
	return false
}

func isRefTakingReferrer(instr ssa.Instruction) bool {
	switch instr.(type) {
	case *ssa.IndexAddr: // taking the address of the index to store sth
		return true
	case *ssa.Index: // taking the index only for reading the value
		return false
	default:
		return true // to be safe, so that we check stores in it
	}
}

func getsStaticData(instr ssa.Instruction) bool {
	asVal, isVal := instr.(ssa.Value)
	if !isVal {
		return false
	}
	for _, referrer := range *asVal.Referrers() {
		if storeInstr, isStore := referrer.(*ssa.Store); isStore {
			if !IsStaticallyDefinedLocal(storeInstr.Val) {
				return false
			}
		}
	}
	return true
}
