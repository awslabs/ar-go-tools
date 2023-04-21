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

package dataflow

import (
	"fmt"
	"go/types"

	"github.com/awslabs/argot/analysis/config"
	. "github.com/awslabs/argot/analysis/functional"
	"golang.org/x/tools/go/ssa"
)

type functionToNode map[*ssa.Function][]ssa.Node

type PackageToNodes map[*ssa.Package]functionToNode

type nodeIdFunction func(*config.Config, ssa.Node) bool

func NewPackagesMap(c *config.Config, pkgs []*ssa.Package, f nodeIdFunction) PackageToNodes {
	packageMap := make(PackageToNodes)
	for _, pkg := range pkgs {
		pkgMap := newPackageMap(c, pkg, f)
		if len(pkgMap) > 0 {
			packageMap[pkg] = pkgMap
		}
	}
	return packageMap
}

func newPackageMap(c *config.Config, pkg *ssa.Package, f nodeIdFunction) functionToNode {
	fMap := make(functionToNode)
	for _, mem := range pkg.Members {
		switch fn := mem.(type) {
		case *ssa.Function:
			populateFunctionMap(c, fMap, fn, f)
		}
	}
	return fMap
}

func populateFunctionMap(config *config.Config, fMap functionToNode, current *ssa.Function, f nodeIdFunction) {
	var sources []ssa.Node
	for _, b := range current.Blocks {
		for _, instr := range b.Instrs {
			// An instruction should always be a Node too.
			if n := instr.(ssa.Node); f(config, n) {
				sources = append(sources, n)
			}
		}
	}
	fMap[current] = sources
}

func FindSafeCalleePkg(n *ssa.CallCommon) Optional[string] {
	if n == nil || n.StaticCallee() == nil || n.StaticCallee().Pkg == nil {
		return None[string]()
	}
	return Some(n.StaticCallee().Pkg.Pkg.Name())
}

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
