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
