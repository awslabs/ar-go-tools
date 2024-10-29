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
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	fn "github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
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
			return fn.Some(pkg.String())
		}
		return fn.None[string]()
	}
	return fn.None[string]()
}

// FieldAddrFieldInfo finds the name of a field access in ssa.FieldAddr
// if it cannot find a proper field name, returns "?".
// The boolean indicates whether this field is embedded or not.
func FieldAddrFieldInfo(fieldAddr *ssa.FieldAddr) (string, bool) {
	return GetFieldInfoFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// FieldFieldInfo finds the name of a field access in ssa.Field
// if it cannot find a proper field name, returns "?".
// The boolean indicates whether this field is embedded or not.
func FieldFieldInfo(fieldAddr *ssa.Field) (string, bool) {
	return GetFieldInfoFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// GetFieldInfoFromType returns the name of field i if t is a struct or pointer to a struct.
// The boolean indicates whether this field is embedded or not.
func GetFieldInfoFromType(t types.Type, i int) (string, bool) {
	switch typ := t.(type) {
	case *types.Pointer:
		return GetFieldInfoFromType(typ.Elem().Underlying(), i) // recursive call
	case *types.Struct:
		// Get the field name given its index
		if 0 <= i && i < typ.NumFields() {
			field := typ.Field(i)
			return field.Name(), field.Embedded()
		}
		return "?", false
	default:
		return "?", false
	}
}

// IsEntrypointNode returns true if n matches a code identifier according to the predicate f
//
//gocyclo:ignore
func IsEntrypointNode(pointer *pointer.Result, n ssa.Node,
	f func(config.CodeIdentifier) bool) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered entry points
	case *ssa.Call:
		if node == nil {
			return false // inits cannot be entry points
		}

		parent := node.Parent()
		if !node.Call.IsInvoke() {
			return isFuncEntrypoint(node, parent, f) || isAliasEntrypoint(pointer, node, f)
		}

		// For invoke also populate the receiver
		receiver := node.Call.Value.Name()
		methodName := node.Call.Method.Name()
		calleePkg := FindSafeCalleePkg(node.Common())
		if calleePkg.IsSome() {
			return f(
				config.CodeIdentifier{
					Context:    parent.String(),
					Package:    calleePkg.Value(),
					Method:     methodName,
					Receiver:   receiver,
					ValueMatch: n.String()})
		}
		return false

	// Field accesses that are considered as entry points
	case *ssa.Field:
		fieldName, _ := FieldFieldInfo(node)
		packageName, typeName, err := FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context:    node.Parent().String(),
			Package:    packageName,
			Field:      fieldName,
			Type:       typeName,
			ValueMatch: n.String()})

	case *ssa.FieldAddr:
		fieldName, _ := FieldAddrFieldInfo(node)
		packageName, typeName, err := FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context:    node.Parent().String(),
			Package:    packageName,
			Field:      fieldName,
			Type:       typeName,
			ValueMatch: n.String()})

	// Allocations of data of a type that is an entry point
	case *ssa.Alloc:
		packageName, typeName, err := FindEltTypePackage(node.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context:    node.Parent().String(),
			Package:    packageName,
			Type:       typeName,
			ValueMatch: n.String()})

	// Storing into a specific struct field
	case *ssa.Store:
		if fieldAddr, isFieldAddr := node.Addr.(*ssa.FieldAddr); isFieldAddr {
			fieldName, _ := FieldAddrFieldInfo(fieldAddr)
			packageName, typeName, err := FindEltTypePackage(fieldAddr.X.Type(), "%s")
			if err != nil {
				return false
			}
			return f(config.CodeIdentifier{
				Context:    node.Parent().String(),
				Package:    packageName,
				Field:      fieldName,
				Type:       typeName,
				Kind:       "store",
				ValueMatch: n.String()})
		}
		return false

	// Channel receives can be sources
	case *ssa.UnOp:
		if node.Op == token.ARROW {
			packageName, typeName, err := FindEltTypePackage(node.X.Type(), "%s")
			if err != nil {
				return false
			}
			return f(config.CodeIdentifier{
				Context:    node.Parent().String(),
				Package:    packageName,
				Type:       typeName,
				Kind:       "channel receive",
				ValueMatch: n.String()})
		}
		return false

	default:
		return false
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

// isFuncEntrypoint returns true if the actual function called matches an entrypoint.
func isFuncEntrypoint(node *ssa.Call, parent *ssa.Function, f func(config.CodeIdentifier) bool) bool {
	funcValue := node.Call.Value.Name()
	calleePkg := FindSafeCalleePkg(node.Common())
	if calleePkg.IsSome() {
		return f(config.CodeIdentifier{Context: parent.String(), Package: calleePkg.Value(), Method: funcValue})
	}
	return false
}

// isAliasEntrypoint returns true if any alias to node matches an entrypoint.
func isAliasEntrypoint(pointer *pointer.Result, node *ssa.Call, f func(config.CodeIdentifier) bool) bool {
	if pointer == nil {
		return false
	}
	ptr, hasAliases := pointer.Queries[node.Call.Value]
	if !hasAliases {
		return false
	}
	for _, label := range ptr.PointsTo().Labels() {
		funcValue := label.Value().Name()
		funcPackage := FindValuePackage(label.Value())
		if funcPackage.IsSome() && f(config.CodeIdentifier{Package: funcPackage.Value(), Method: funcValue}) {
			return true
		}
	}
	return false
}
