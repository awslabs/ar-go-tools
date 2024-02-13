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
	"strings"

	"golang.org/x/tools/go/ssa"

	fn "github.com/awslabs/ar-go-tools/internal/funcutil"
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

// FindTypeByName finds the given type from the given package, if it exists. Otherwise, returns nil
func FindTypeByName(prog *ssa.Program, pkg string, tpName string) types.Type {
	ssaPkg := prog.ImportedPackage(pkg)
	if ssaPkg == nil {
		return nil
	}
	tpObj := ssaPkg.Pkg.Scope().Lookup(tpName)
	if tpObj == nil {
		return nil
	}
	return tpObj.Type()
}

// IsAnyType tests whether the type is equivalent to the `any` type
func IsAnyType(tp types.Type) bool {
	if inter, ok := tp.Underlying().(*types.Interface); ok {
		return inter.Empty()
	}
	return false
}

// GetPackageOfType finds the type.Package for a type. Does not require any ssa.* objects
func GetPackageOfType(tp types.Type) *types.Package {
	if obj, ok := tp.(types.Object); ok {
		return obj.Pkg()
	} else if named, ok := tp.(*types.Named); ok {
		return named.Obj().Pkg()
	}
	return nil
}

// FindImplementationMethod looks up the ssa.Function for a reciever value of type tp when called
// for the given interface type and method name. This could require adding a pointer indirection if
// the given tp is e.g. a struct type, so the function also returns a boolean indicating if this is
// necessary.
func FindImplementationMethod(prog *ssa.Program, tp types.Type, iface types.Type, methodName string) (method *ssa.Function, pointerRequired bool) {
	if types.AssignableTo(tp, iface) {
		pkg := GetPackageOfType(tp)
		return prog.LookupMethod(tp, pkg, methodName), false
	} else if types.AssignableTo(types.NewPointer(tp), iface) {
		pkg := GetPackageOfType(tp)
		return prog.LookupMethod(types.NewPointer(tp), pkg, methodName), true
	}
	return nil, false
}
