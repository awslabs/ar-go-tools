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
	"go/token"
	"go/types"
	"strings"

	fn "github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// at this point, the f.String contains something like this:
// (*net/http.requestBodyReadError).Error
// (encoding/json.jsonError).Error
// (*github.com/aws/aws-sdk-go/aws/endpoints.EndpointNotFoundError).Error

func packageFromErrorName(name string) string {
	if !strings.HasSuffix(name, ").Error") {
		return ""
	}
	name = name[:len(name)-7]
	if !strings.HasPrefix(name, "(") {
		return ""
	}
	name = name[1:]
	if strings.HasPrefix(name, "*") {
		name = name[1:]
	}
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[:i]
}

// PackageTypeFromFunction returns the package associated with a function
// If the function has a package, return that.
// If the function is a method, return the package of its object
func PackageTypeFromFunction(f *ssa.Function) *types.Package {
	pkg := f.Package()
	if pkg != nil {
		return pkg.Pkg
	}

	// f.Object can happen with some generics
	if f.Object() == nil {
		return nil
	}

	obj := f.Object().Pkg()
	if obj != nil {
		return obj
	}

	// could just return obj, but we're explicit about returning nil
	return nil
}

// PackageNameFromFunction returns the best possible package name for a ssa.Function
// If the Function has a package, use that.
// If the function doesn't have a package, check if it's a method and use
// the package associated with its object
// If none of those are true, it must be an error, so try to extract the package
// name from the various error formats.
func PackageNameFromFunction(f *ssa.Function) string {
	if f == nil {
		return ""
	}

	pkg := f.Package()
	if pkg != nil {
		return pkg.Pkg.Path()
	}

	// this is a method, so need to get its Object first
	if f.Object() != nil {
		obj := f.Object().Pkg()
		if obj != nil {
			return obj.Path()
		}

		name := packageFromErrorName(f.String())
		if name != "" {
			return name
		}
	}

	return ""
}

// DummyPos is a dummy position returned to indicate that no position could be found.
// Can also be used when generating code, and the generated code has no position.
var DummyPos = token.Position{
	Filename: "unknown",
	Offset:   -1,
	Line:     -1,
	Column:   -1,
}

// SafeFunctionPos returns the position of the function without panicking
func SafeFunctionPos(function *ssa.Function) fn.Optional[token.Position] {
	if function.Prog != nil && function.Prog.Fset != nil {
		return fn.Some(function.Prog.Fset.Position(function.Pos()))
	}
	return fn.None[token.Position]()
}

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
	case *types.Basic, *types.Tuple, *types.Interface, *types.Signature:
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
			return fn.Some(pkg.Pkg.Path())
		}
		return fn.None[string]()
	}
	return fn.None[string]()
}

// FieldAddrFieldName finds the name of a field access in ssa.FieldAddr
// if it cannot find a proper field name, returns "?"
func FieldAddrFieldName(fieldAddr *ssa.FieldAddr) string {
	return GetFieldNameFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// FieldFieldName finds the name of a field access in ssa.Field
// if it cannot find a proper field name, returns "?"
func FieldFieldName(fieldAddr *ssa.Field) string {
	return GetFieldNameFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// GetFieldNameFromType returns the name of field i if t is a struct or pointer to a struct
func GetFieldNameFromType(t types.Type, i int) string {
	switch typ := t.(type) {
	case *types.Pointer:
		return GetFieldNameFromType(typ.Elem().Underlying(), i) // recursive call
	case *types.Struct:
		// Get the field name given its index
		fieldName := "?"
		if 0 <= i && i < typ.NumFields() {
			fieldName = typ.Field(i).Name()
		}
		return fieldName
	default:
		return "?"
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
