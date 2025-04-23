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

// Package analysisutil contains utility functions for the analyses in argot.
// These functions are in an internal package because they are not important
// enough to be included in the main library.
package analysisutil

import (
	"fmt"
	"go/types"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	fn "github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// FindEltTypePackage finds the package declaring the elements of t or returns an error
// Returns a package name and the name of the type declared in that package.
// preform is the formatting of the type of the element; usually %s
func FindEltTypePackage(t types.Type, preform string) (string, string, error) {
	switch typ := t.(type) {
	case *types.Pointer:
		return FindEltTypePackage(typ.Elem(), fmt.Sprintf(preform, "*%s")) // recursive call
	case *types.Named:
		// Return package name, type name
		obj := typ.Obj()
		if obj != nil {
			pkg := obj.Pkg()
			if pkg != nil {
				return pkg.Name(), fmt.Sprintf(preform, obj.Name()), nil
			}
			// obj is in Universe
			return "", obj.Name(), nil

		}
		return "", "", fmt.Errorf("could not get name")

	case *types.Array:
		n := typ.Len()
		p := fmt.Sprintf(preform, fmt.Sprintf("[%v]", n)+"%s")
		return FindEltTypePackage(typ.Elem(), p) // recursive call
	case *types.Map:
		return FindEltTypePackage(typ.Elem(), fmt.Sprintf(preform, "map["+typ.Key().String()+"]%s")) // recursive call
	case *types.Slice:
		return FindEltTypePackage(typ.Elem(), fmt.Sprintf(preform, "[]%s")) // recursive call
	case *types.Chan:
		return FindEltTypePackage(typ.Elem(), fmt.Sprintf(preform, "chan %s")) // recursive call
	case *types.Basic:
		return "", typ.Name(), nil
	case *types.Tuple, *types.Interface, *types.Signature:
		// We ignore this for now (tuple may involve multiple packages)
		return "", "", fmt.Errorf("not a type with a package and name")
	case *types.Struct:
		// Anonymous structs
		return "", "", fmt.Errorf("%q: not a type with a package and name", typ)
	default:
		// We should never reach this!
		fmt.Printf("unexpected type received: %T %v; please report this issue\n", typ, typ)
		return "", "", nil
	}
}

// FindSafeCalleePkg finds the packages of the callee in the ssa.CallCommon without panicking
func FindSafeCalleePkg(n *ssa.CallCommon) fn.Optional[string] {
	if n == nil {
		return fn.None[string]()
	}
	if n.IsInvoke() && n.Method != nil {
		if pkg := n.Method.Pkg(); pkg != nil {
			return fn.Some(pkg.Path())
		}
		return fn.None[string]()
	}
	if n.StaticCallee() == nil || n.StaticCallee().Pkg == nil {
		return fn.None[string]()
	}

	return fn.Some(n.StaticCallee().Pkg.Pkg.Path())
}

// FindValuePackage finds the package of n.
// Returns None if no package was found.
func FindValuePackage(n ssa.Value) fn.Optional[string] {
	switch node := n.(type) {
	case *ssa.Function:
		pkg := node.Package()
		if node.Signature.Recv() != nil {
			// the package of a method is the package of its receiver
			pkg = node.Params[0].Parent().Package()
		}
		if pkg != nil {
			return fn.Some(pkg.String())
		}
		return fn.None[string]()
	}
	return fn.None[string]()
}

// FieldInfo is information about a struct field.
type FieldInfo struct {
	Field      *types.Var
	FieldName  string
	Struct     *types.Struct
	IsEmbedded bool
}

// FieldAddrFieldInfo finds the name of a field access in ssa.FieldAddr
// if it cannot find a proper field name, returns "?".
// The boolean indicates whether this field is embedded or not.
func FieldAddrFieldInfo(fieldAddr *ssa.FieldAddr) FieldInfo {
	return GetFieldInfoFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// FieldFieldInfo finds the name of a field access in ssa.Field
// if it cannot find a proper field name, returns "?".
// The boolean indicates whether this field is embedded or not.
func FieldFieldInfo(fieldAddr *ssa.Field) FieldInfo {
	return GetFieldInfoFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// GetFieldInfoFromType returns the name of field i if t is a struct or pointer to a struct.
// The boolean indicates whether this field is embedded or not.
func GetFieldInfoFromType(t types.Type, i int) FieldInfo {
	switch typ := t.(type) {
	case *types.Pointer:
		return GetFieldInfoFromType(typ.Elem().Underlying(), i) // recursive call
	case *types.Struct:
		// Get the field name given its index
		if 0 <= i && i < typ.NumFields() {
			field := typ.Field(i)
			return FieldInfo{
				Field:      field,
				FieldName:  field.Name(),
				Struct:     typ,
				IsEmbedded: field.Embedded(),
			}
		}
		return FieldInfo{Struct: typ}
	default:
		return FieldInfo{}
	}
}

// ReceiverStr returns the string receiver name of t.
// e.g. *repo/package.Method -> Method
// TODO refactor to avoid string operations
func ReceiverStr(t types.Type) string {
	typ := t.String()
	// get rid of pointer prefix in type name
	typ = strings.Replace(typ, "*", "", -1)
	split := strings.Split(typ, ".")
	return split[len(split)-1]
}

// ParamTypStr returns a type string for the parameter, with handling of variadic parameters where
// the slice type is replaced by the type followed by three dots
func ParamTypStr(param lang.Param, idx int, arg ssa.Value) string {
	typ := arg.Type().String()
	if param.IsVariadic {
		// If the parameter type is variadic, the SSA form of the argument will be a slice
		// (`[]type`) instead of the `...type` form.
		typ = strings.TrimPrefix(typ, "[]")
		typ = "..." + typ
	}
	return typ
}
