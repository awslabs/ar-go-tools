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
	"fmt"
	"go/types"

	"github.com/dave/dst"
)

// ZeroValueExpr returns the zero-value of a type typ, or an error when it could not find a zero value
func ZeroValueExpr(typ types.Type) (dst.Expr, error) {
	switch t := typ.(type) {
	case *types.Basic:
		// A basic type
		return zeroValueOfBasicType(t)
	case *types.Struct:
		// A struct
		return zeroValueOfStruct(t)
	case *types.Named:
		return NewNil(), nil
	default:
		return NewNil(), nil
	}
}

// zeroValueOfBasicType returns the zero value expression of a basic type. For example, the zero value of
// types.Int is a basic literal with value 0
func zeroValueOfBasicType(t *types.Basic) (dst.Expr, error) {
	switch t.Kind() {
	case types.Invalid:
		return nil, fmt.Errorf("cannot generate value of invalid type")
		// predeclared types
	case types.Bool:
		return NewFalse(), nil
	case types.Int, types.Int8, types.Int16, types.Int32, types.Int64:
		return NewInt(0), nil
	case types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64: // covers types.Byte, types.Rune
		return NewInt(0), nil
	case types.Uintptr:
		return NewInt(0), nil
	case types.Float32:
		return NewFloat32(0.0), nil
	case types.Float64:
		return NewFloat64(0.0), nil
	case types.Complex64, types.Complex128:
		return nil, fmt.Errorf("generation of complex types not supported")
	case types.String:
		return NewString(""), nil
	case types.UnsafePointer:
		return nil, fmt.Errorf("cannot generate default value of unsafe pointer")

	case types.UntypedBool, types.UntypedInt, types.UntypedRune, types.UntypedFloat,
		types.UntypedComplex, types.UntypedString, types.UntypedNil:
		return nil, fmt.Errorf("cannot generate default value of untyped value")
	default:
		return nil, fmt.Errorf("unexpected type in exhaustive switch")
	}
}

// zeroValueOfStruct returns tue zero value expression of a struct type.
// For example:
//
//	struct {
//			y int
//			x float32
//		}{}
//
// The fields are never given a value.
func zeroValueOfStruct(t *types.Struct) (dst.Expr, error) {
	typeExpr, err := NewTypeExpr(t)
	if err != nil {
		return nil, err
	}
	e := &dst.CompositeLit{
		Type:       typeExpr,
		Elts:       []dst.Expr{},
		Incomplete: false,
	}
	return e, nil
}
