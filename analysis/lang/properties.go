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
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// IsNillableType returns true if t is a type that can have the nil value.
func IsNillableType(t types.Type) bool {
	switch t.(type) {
	case *types.Pointer, *types.Interface, *types.Slice, *types.Map, *types.Chan:
		return true
	case *types.Named:
		return IsNillableType(t.Underlying())
	case *types.Signature:
		return true
	default:
		return false
	}
}

// IsErrorType returns true if t is the error type
func IsErrorType(t types.Type) bool {
	// Only the error type can have "error" as representation
	if t.String() == "error" {
		return true
	}
	interfaceTyp, ok := t.(*types.Interface)
	if !ok {
		return false
	}
	return interfaceTyp.NumMethods() == 1 && interfaceTyp.ExplicitMethod(0).Name() == "Error"
}

// IsChannelEnclosingType return true if the type is a pointer to channel, a channel, or a data structure containing
// a channel
func IsChannelEnclosingType(t types.Type) bool {
	visitedTypes := map[types.Type]bool{}
	toVisit := []types.Type{t}
	addNext := func(t types.Type) {
		if !visitedTypes[t] {
			toVisit = append(toVisit, t)
		}
	}
	for len(toVisit) > 0 {
		head := toVisit[0]
		toVisit = toVisit[1:]
		visitedTypes[head] = true
		switch typ := head.Underlying().(type) {
		case *types.Chan:
			return true
		case *types.Pointer:
			addNext(typ.Elem())
		case *types.Slice:
			addNext(typ.Elem())
		case *types.Map:
			addNext(typ.Elem())
		case *types.Array:
			addNext(typ.Elem())
		case *types.Tuple:
			n := typ.Len()
			for i := 0; i < n; i++ {
				addNext(typ.At(i).Type())
			}
		case *types.Struct:
			n := typ.NumFields()
			for i := 0; i < n; i++ {
				addNext(typ.Field(i).Type())
			}

		}
	}
	return false
}

// IsReturningFunctionType returns true if typ is the type of a function that returns values
func IsReturningFunctionType(typ types.Type) bool {
	sig, isSig := typ.(*types.Signature)
	if !isSig {
		return false
	}
	return sig.Results() != nil
}

// IsValueReturningCall returns true if value is a call that returns some value
func IsValueReturningCall(value ssa.Value) bool {
	call, isCall := value.(*ssa.Call)
	if !isCall || call == nil {
		return false
	}
	return IsReturningFunctionType(call.Common().Signature())
}

// IsPredicateFunctionType returns true if f is a function that can be interpreted as a predicate
// A function is a predicate if its last argument is either a boolean or an error.
func IsPredicateFunctionType(f *types.Signature) bool {
	if f == nil {
		return false
	}

	n := f.Results().Len()
	if n <= 0 {
		return false
	}

	resType := f.Results().At(n - 1)
	if resType == nil {
		return false
	}
	switch t := resType.Type().Underlying().(type) {
	case *types.Basic:
		return t.Kind() == types.Bool
	case *types.Interface:
		return IsErrorType(t)
	default:
		return false
	}
}
