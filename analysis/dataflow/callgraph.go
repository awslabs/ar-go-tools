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
	"go/types"
	"sync/atomic"

	"golang.org/x/tools/go/ssa"
)

// SsaInfo is holds all the information from a built ssa program with main packages
type SsaInfo struct {
	Prog     *ssa.Program
	Packages []*ssa.Package
	Mains    []*ssa.Package
}

// This global variable should only be read and modified through GetUniqueFunctionID
var uniqueFunctionIDCounter uint32 = 0

// GetUniqueFunctionID increments and returns the Value of the global used to give unique function ids.
func GetUniqueFunctionID() uint32 {
	x := atomic.AddUint32(&uniqueFunctionIDCounter, 1)
	return x
}

// ComputeMethodImplementations populates a map from method implementation type string to the different implementations
// corresponding to that method.
// The map can be indexed by using the signature of an interface method and calling String() on it.
// If the provided contracts map is non-nil, then the function also builds a summary graph for each interface
// method such that contracts[methodId] = nil
func ComputeMethodImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool,
	contracts map[string]*SummaryGraph, keys map[string]string) error {
	interfaceTypes := map[*ssa.Type]map[string]*types.Selection{}
	signatureTypes := map[string]bool{} // TODO: use this to index function by signature
	// Fetch all interface types
	for _, pkg := range p.AllPackages() {
		for _, mem := range pkg.Members {
			switch memType := mem.(type) {
			case *ssa.Type:
				switch iType := memType.Type().Underlying().(type) {
				case *types.Interface:
					interfaceTypes[memType] = methodSetToNameMap(p.MethodSets.MethodSet(memType.Type()))
				case *types.Signature:
					signatureTypes[iType.String()] = true
				}
			}
		}
	}

	// Fetch implementations of all interface methods

	for interfaceType, interfaceMethods := range interfaceTypes {
		for _, typ := range p.RuntimeTypes() {
			// Find the interfaces it implements (type conversion cannot fail)
			if types.Implements(typ.Underlying(), interfaceType.Type().Underlying().(*types.Interface)) {
				set := p.MethodSets.MethodSet(typ)
				for i := 0; i < set.Len(); i++ {
					method := set.At(i)
					// Get the function implementation
					methodValue := p.MethodValue(method)
					if methodValue == nil {
						continue
					}
					// Get the interface method being implemented
					matchingInterfaceMethod := interfaceMethods[methodValue.Name()]
					if matchingInterfaceMethod != nil {
						key := matchingInterfaceMethod.Recv().String() + "." + methodValue.Name()
						keys[methodValue.String()] = key
						addImplementation(implementations, key, methodValue)
						addContractSummaryGraph(contracts, key, methodValue, GetUniqueFunctionID())
					}
				}
			}
		}
	}

	computeErrorBuiltinImplementations(p, implementations, contracts, keys)

	return nil
}

// computeErrorBuiltinImplementations adds the implementations of the builtin error interface (the error.Error method)
// to the implementations map
func computeErrorBuiltinImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool,
	contracts map[string]*SummaryGraph, keys map[string]string) {
	key := "error.Error"
	for _, typ := range p.RuntimeTypes() {
		set := p.MethodSets.MethodSet(typ)
		// Does it implement the error builtin?
		for i := 0; i < set.Len(); i++ {
			method := set.At(i)
			// Get the function implementation
			methodValue := p.MethodValue(method)
			if methodValue == nil || methodValue.Name() != "Error" || len(methodValue.Params) > 1 {
				continue
			}
			results := methodValue.Signature.Results()
			if results.Len() != 1 {
				continue
			}
			expectedString := results.At(0).Type().Underlying()
			if expectedString.String() != "string" {
				continue
			}

			keys[methodValue.String()] = key
			// Get the interface method being implemented
			addImplementation(implementations, key, methodValue)
			addContractSummaryGraph(contracts, key, methodValue, GetUniqueFunctionID())
		}
	}
}

// addImplementation sets the Value of key in implementationsMap to function, handling the creation of nested maps.
// @requires implementationMap != nil
func addImplementation(implementationMap map[string]map[*ssa.Function]bool, key string, function *ssa.Function) {
	if implementations, ok := implementationMap[key]; ok {
		if !implementations[function] {
			implementationMap[key][function] = true
		}
	} else {
		implementationMap[key] = map[*ssa.Function]bool{function: true}
	}
}

// addContractSummaryGraph sets the Value of contract[methodId] to a new summary of function if the methodId key
// is present in contracts but the associated Value is nil
// Does nothing if contracts is nil.
func addContractSummaryGraph(contracts map[string]*SummaryGraph, methodID string, function *ssa.Function, id uint32) {
	if contracts == nil || function == nil {
		return
	}
	// Entry must be present
	if curSummary, ok := contracts[methodID]; ok {
		if curSummary == nil {
			contracts[methodID] = NewSummaryGraph(nil, function, id, nil, nil)
		}
	}
}

func methodSetToNameMap(methodSet *types.MethodSet) map[string]*types.Selection {
	nameMap := map[string]*types.Selection{}

	for i := 0; i < methodSet.Len(); i++ {
		method := methodSet.At(i)
		nameMap[method.Obj().Name()] = method
	}
	return nameMap
}
