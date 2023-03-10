package ssafuncs

import (
	"golang.org/x/tools/go/ssa"
)

// IterateInstructions iterates through all the instructions in the function, in no specific order.
// It ignores the order in which blocks should be executed.
func IterateInstructions(function *ssa.Function, f func(instruction ssa.Instruction)) {
	// If this is an external function, return.
	if function.Blocks == nil {
		return
	}

	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			f(instruction)
		}
	}
}

// IterateValues applies f to every value in the function. It might apply f several times to the same value
func IterateValues(function *ssa.Function, f func(value ssa.Value)) {
	for _, param := range function.Params {
		f(param)
	}

	for _, freeVar := range function.FreeVars {
		f(freeVar)
	}

	IterateInstructions(function, func(i ssa.Instruction) {
		var operands []*ssa.Value
		operands = i.Operands(operands)
		for _, operand := range operands {
			f(*operand)
		}
		if v, ok := i.(ssa.Value); ok {
			f(v)
		}
	})
}
