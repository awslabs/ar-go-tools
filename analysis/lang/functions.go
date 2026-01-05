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

// IsExternal returns true if function is external (in ssa, when Blocks is nil)
func IsExternal(function *ssa.Function) bool {
	// This is indicated in the ssa documentation
	return function.Blocks == nil
}

// IterateInstructions iterates through all the instructions in the function, in no specific order.
// It ignores the order in which blocks should be executed, but always starts with the first block.
func IterateInstructions(function *ssa.Function, f func(index int, instruction ssa.Instruction)) {
	// If this is an external function, return.
	if function.Blocks == nil {
		return
	}

	for _, block := range function.Blocks {
		for index, instruction := range block.Instrs {
			f(index, instruction)
		}
	}
}

// IterateValues applies f to every value in the function. It might apply f several times to the same value
// if the value is from an instruction, the index of the instruction in the block will be provided, otherwise a value
// of -1 indicating the value is not in an instruction is given to the function.
func IterateValues(function *ssa.Function, f func(index int, value ssa.Value)) {
	for _, param := range function.Params {
		f(-1, param)
	}

	for _, freeVar := range function.FreeVars {
		f(-1, freeVar)
	}

	IterateInstructions(function, func(index int, i ssa.Instruction) {
		var operands []*ssa.Value
		operands = i.Operands(operands)
		for _, operand := range operands {
			f(index, *operand)
		}
		if v, ok := i.(ssa.Value); ok {
			f(index, v)
		}
	})
}

// MethodKey returns the key that would be used in the result of ComputeMethodImplementations for the method with name
// methodName in the interface receiver
func MethodKey(receiver string, methodName string) string {
	return receiver + "." + methodName
}

// ComputeMethodImplementations populates a map from method implementation type string to the different implementations
// corresponding to that method.
// The map can be indexed by using the signature of an interface method and calling String() on it.
func ComputeMethodImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool,
	keys map[string]string) error {
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
					if matchingInterfaceMethod == nil {
						continue
					}
					receiver := matchingInterfaceMethod.Recv()
					if receiver == nil {
						continue
					}
					key := MethodKey(receiver.String(), methodValue.Name())
					keys[methodValue.String()] = key
					addImplementation(implementations, key, methodValue)
				}
			}
		}
	}

	computeErrorBuiltinImplementations(p, implementations, keys)

	return nil
}

// computeErrorBuiltinImplementations adds the implementations of the builtin error interface (the error.Error method)
// to the implementations map
func computeErrorBuiltinImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool,
	keys map[string]string) {
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
			res0typ := results.At(0).Type()
			if res0typ == nil {
				continue
			}
			expectedString := res0typ.Underlying()
			if expectedString.String() != "string" {
				continue
			}

			keys[methodValue.String()] = key
			// Get the interface method being implemented
			addImplementation(implementations, key, methodValue)
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

func methodSetToNameMap(methodSet *types.MethodSet) map[string]*types.Selection {
	nameMap := map[string]*types.Selection{}

	for i := 0; i < methodSet.Len(); i++ {
		method := methodSet.At(i)
		nameMap[method.Obj().Name()] = method
	}
	return nameMap
}
