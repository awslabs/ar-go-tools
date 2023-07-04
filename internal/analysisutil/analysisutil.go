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

	"github.com/awslabs/ar-go-tools/analysis/config"
	. "github.com/awslabs/ar-go-tools/internal/funcutil"

	"golang.org/x/tools/go/ssa"
)

// FindTypePackage finds the package declaring t or returns an error
// Returns a package name and the name of the type declared in that package
func FindTypePackage(t types.Type) (string, string, error) {
	switch typ := t.(type) {
	case *types.Pointer:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Named:
		// Return package name, type name
		obj := typ.Obj()
		if obj != nil {
			pkg := obj.Pkg()
			if pkg != nil {
				return pkg.Name(), obj.Name(), nil
			} else {
				// obj is in Universe
				return "", obj.Name(), nil
			}

		} else {
			return "", "", fmt.Errorf("could not get name")
		}

	case *types.Array:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Map:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Slice:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Chan:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Basic, *types.Tuple, *types.Interface, *types.Signature:
		// We ignore this for now (tuple may involve multiple packages)
		return "", "", fmt.Errorf("not a type with a package and name")
	case *types.Struct:
		// Anonymous structs
		return "", "", fmt.Errorf("%s: not a type with a package and name", typ)
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
		return Some(n.Method.Pkg().Path())
	}
	if n.StaticCallee() == nil || n.StaticCallee().Pkg == nil {
		return None[string]()
	}

	return Some(n.StaticCallee().Pkg.Pkg.Path())
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

// IsEntrypointNode returns true if n is an entrypoint to the intra-procedural analysis according to f.
func IsEntrypointNode(cfg *config.Config, n ssa.Node, f func(config.Config, config.CodeIdentifier) bool) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered entry points
	case *ssa.Call:
		if node == nil {
			return false // inits cannot be entry points
		}
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg := FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return f(*cfg, config.CodeIdentifier{Package: calleePkg.Value(), Method: methodName, Receiver: receiver})
			} else {
				return false
			}
		} else {
			funcValue := node.Call.Value.Name()
			calleePkg := FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return f(*cfg, config.CodeIdentifier{Package: calleePkg.Value(), Method: funcValue})
			} else {
				return false
			}
		}

	// Field accesses that are considered as entry points
	case *ssa.Field:
		fieldName := FieldFieldName(node)
		packageName, typeName, err := FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return f(*cfg, config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	case *ssa.FieldAddr:
		fieldName := FieldAddrFieldName(node)
		packageName, typeName, err := FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return f(*cfg, config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	// Allocations of data of a type that is an entry point
	case *ssa.Alloc:
		packageName, typeName, err := FindTypePackage(node.Type())
		if err != nil {
			return false
		} else {
			return f(*cfg, config.CodeIdentifier{Package: packageName, Type: typeName})
		}

	default:
		return false
	}
}
