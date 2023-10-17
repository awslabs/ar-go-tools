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
	"go/token"
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/config"
	. "github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/pointer"

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
			} else {
				// obj is in Universe
				return "", obj.Name(), nil
			}

		} else {
			return "", "", fmt.Errorf("could not get name")
		}

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

func FindSafeCalleePkg(n *ssa.CallCommon) Optional[string] {
	if n == nil {
		return None[string]()
	}
	if n.IsInvoke() && n.Method != nil {
		if pkg := n.Method.Pkg(); pkg != nil {
			return Some(pkg.Path())
		}
		return None[string]()
	}
	if n.StaticCallee() == nil || n.StaticCallee().Pkg == nil {
		return None[string]()
	}

	return Some(n.StaticCallee().Pkg.Pkg.Path())
}

func FindValuePackage(n ssa.Value) Optional[string] {
	switch node := n.(type) {
	case *ssa.Function:
		pkg := node.Package()
		if pkg != nil {
			return Some(pkg.String())
		}
		return None[string]()
	}
	return None[string]()
}

// FieldAddrFieldName finds the name of a field access in ssa.FieldAddr
// if it cannot find a proper field name, returns "?"
func FieldAddrFieldName(fieldAddr *ssa.FieldAddr) string {
	return getFieldNameFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// FieldFieldName finds the name of a field access in ssa.Field
// if it cannot find a proper field name, returns "?"
func FieldFieldName(fieldAddr *ssa.Field) string {
	return getFieldNameFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

func getFieldNameFromType(t types.Type, i int) string {
	switch typ := t.(type) {
	case *types.Pointer:
		return getFieldNameFromType(typ.Elem().Underlying(), i) // recursive call
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

// IsEntrypointNode returns true if n is an entrypoint to the analysis according to f.
func IsEntrypointNode(pointer *pointer.Result, n ssa.Node, f func(config.CodeIdentifier) bool) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered entry points
	case *ssa.Call:
		if node == nil {
			return false // inits cannot be entry points
		}

		parent := node.Parent()
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg := FindSafeCalleePkg(node.Common())
      if calleePkg.IsSome() {
				return f(
					config.CodeIdentifier{
						Context:  parent.String(),
						Package:  calleePkg.Value(),
						Method:   methodName,
						Receiver: receiver})
			}
			return false
		}
		// Check if the actual function called matches an entrypoint
		funcValue := node.Call.Value.Name()
		calleePkg := FindSafeCalleePkg(node.Common())
    if calleePkg.IsSome() && f(config.CodeIdentifier{Context: parent.String(), Package: calleePkg.Value(), Method: funcValue}) {
			return true
		}
		// Check if any alias matches an entrypoint
		if pointer == nil {
			return false
		}
		ptr, hasAliases := pointer.Queries[node.Call.Value]
		if !hasAliases {
			return false
		}
		for _, label := range ptr.PointsTo().Labels() {
			funcValue = label.Value().Name()
			funcPackage := FindValuePackage(label.Value())
      if funcPackage.IsSome() && f(config.CodeIdentifier{Package: funcPackage.Value(), Method: funcValue}) {
				return true
			}
		}
		return false

	// Field accesses that are considered as entry points
	case *ssa.Field:
		fieldName := FieldFieldName(node)
		packageName, typeName, err := FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context: node.Parent().String(),
			Package: packageName,
			Field:   fieldName,
			Type:    typeName})

	case *ssa.FieldAddr:
		fieldName := FieldAddrFieldName(node)
		packageName, typeName, err := FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context: node.Parent().String(),
			Package: packageName,
			Field:   fieldName,
			Type:    typeName})

	// Allocations of data of a type that is an entry point
	case *ssa.Alloc:
		packageName, typeName, err := FindEltTypePackage(node.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context: node.Parent().String(),
			Package: packageName,
			Type:    typeName})

	// Channel receives can be sources
	case *ssa.UnOp:
		if node.Op == token.ARROW {
			packageName, typeName, err := FindEltTypePackage(node.X.Type(), "%s")
			if err != nil {
				return false
			}
			return f(config.CodeIdentifier{
				Context: node.Parent().String(),
				Package: packageName,
				Type:    typeName,
				Kind:    "channel receive"})
		}
		return false

	default:
		return false
	}
}
