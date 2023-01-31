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
