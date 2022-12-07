// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package analysis

import (
	"fmt"
	"sort"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// A stack is a representation of the runtime stack of defered expressions
// (represented by a slice of the indices of instructions that generated each deferred function)
// A stackSet is a set of stacks, represented as a sorted slice.
// We use indices to represent instructions so that we can compare them (instructions do not know
// their own index).
type InstrIndices struct {
	Block int // index of block in function
	Ins   int // index of instruction in block
}
type Stack []InstrIndices
type StackSet []Stack

// This analysis determines which set of defer instructions can reach each program point.
// For now, everything except whether the result is bounded is thrown away.
// The analysis could be easily extended to save the results at e.g. each RunDefers or each
// panic point.
type DeferResults struct {
	DeferStackBounded bool // unbounded == "bad" == false
	RunDeferSets      map[*ssa.RunDefers]StackSet
}

// A stack set that is empty. Subtly different from a stack set of a single empty stack!
// A stack set that is empty represents no control flow paths reach that point.
// A stack set with a single empty stack means control flow reaches there with no defers.
func stackSetEmpty() StackSet {
	return StackSet{}
}

// Compares two stacks for their order. Result can be compared to zero:
//   a < b <--> stackCompare(a, b) < 0
//   a = b <--> stackCompare(a, b) = 0
//   a > b <--> stackCompare(a, b) > 0
func stackCompare(a Stack, b Stack) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		a_ins, b_ins := a[i], b[i]
		if a_ins.Block < b_ins.Block {
			return -1
		}
		if a_ins.Block > b_ins.Block {
			return 1
		}
		if a_ins.Ins < b_ins.Ins {
			return -1
		}
		if a_ins.Ins > b_ins.Ins {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// Takes the union of two stack sets, and return whether the result is the same as `a` (first arg)
func stackSetUnion(a StackSet, b StackSet) (r StackSet, sameAsA bool) {
	r = []Stack{}
	sameAsA = true
	aIndex, bIndex := 0, 0

	// main merge, as long as there are elements from both
	for aIndex < len(a) && bIndex < len(b) {
		aStack, bStack := a[aIndex], b[bIndex]
		cmp := stackCompare(aStack, bStack)
		if cmp < 0 {
			r = append(r, aStack)
			aIndex++
		} else if cmp > 0 {
			r = append(r, bStack)
			bIndex++
			// inserted new value from b
			sameAsA = false
		} else {
			r = append(r, aStack)
			aIndex++
			bIndex++
		}
	}

	// Only at most one of the following loops will have non-zero iterations:
	// Add remaining elements from a
	for aIndex < len(a) {
		aStack := a[aIndex]
		r = append(r, aStack)
		aIndex++
	}

	// Add remaining elements from b
	for bIndex < len(b) {
		bStack := b[bIndex]
		r = append(r, bStack)
		bIndex++
		// inserted new value from b
		sameAsA = false
	}

	return r, sameAsA
}

// Append {block, ins} to the stack. Ensures that the stack is always copied, so that
// the stacks are treated as value types, i.e. are immutable.
func stackPushed(s Stack, block int, ins int) Stack {
	return append(s[0:len(s):len(s)], InstrIndices{
		block,
		ins})
}

// Computes the "transfer function" of an instruction: maps an stack set from the
// program point right before a function to the set right after that instruction.
func dataflowTransfer(block int, ins int, instr *ssa.Instruction, initial StackSet) (final StackSet, repeated bool) {
	switch (*instr).(type) {
	case *ssa.Defer:
		newStacks := []Stack{}
		repeated = false
		// For each stack, if the current instruction is already there, keep the stack as is
		// Otherwise, append the current instruction
		for _, stack := range initial {
			var thisStackRepeated = false
			for _, entry := range stack {
				if entry.Block == block && entry.Ins == ins {
					thisStackRepeated = true
				}
			}
			if thisStackRepeated {
				repeated = true
				newStacks = append(newStacks, stack)
			} else {
				newStacks = append(newStacks, stackPushed(stack, block, ins))
			}
		}
		// We might have changed the sort order and introduced duplicates. Sort and de-duplicate
		sort.Slice(newStacks, func(i, j int) bool { return stackCompare(newStacks[i], newStacks[j]) < 0 })
		if len(newStacks) > 0 {
			final = []Stack{newStacks[0]}
			for _, s := range newStacks[1:] {
				if stackCompare(final[len(final)-1], s) != 0 {
					final = append(final, s)
				}
			}
		} else {
			final = []Stack{}
		}
		return final, repeated
	case *ssa.RunDefers:
		return StackSet{Stack{}}, false
	default:
		return initial, false
	}
}

// Analyzes a single function using a fixpoint loop
func AnalyzeFunctionDefers(fn *ssa.Function, verbose bool) DeferResults {
	// The preorder should make the analysis converge faster
	blocks := fn.DomPreorder()
	if len(blocks) == 0 {
		// Early out for external functions (no basic blocks)
		return DeferResults{true, map[*ssa.RunDefers]StackSet{}}
	}
	// blockInitialStates represent the dataflow information on entry to each block
	dataflowBlockInitialStates := make([]StackSet, len(blocks))
	// Change flags are a poor man's work list
	dataflowBlockChanged := make([]bool, len(blocks))
	for _, b := range blocks {
		dataflowBlockInitialStates[b.Index] = stackSetEmpty()
		dataflowBlockChanged[b.Index] = false
	}
	// Entry block starts with a single empty stack, and we mark it as changed
	dataflowBlockInitialStates[0] = StackSet{Stack{}}
	dataflowBlockChanged[0] = true

	// Save the set of stacks at each RunDefers instruction
	runDeferSets := map[*ssa.RunDefers]StackSet{}

	// Because the stacks are not bounded, we need to decide on how many iterations to perform.
	// With the change tracking and preorder, we might be able to get away with a fixed iteration count,
	// but this limit ensures that no matter what order we do it in, we'll converge if it is bounded.
	var anyRepeated = false
	for {
		var iterationChanged = false
		// fmt.Printf("Changed: %v\n", dataflowBlockChanged)
		for _, b := range blocks {
			i := b.Index
			// Early out if the initial set is the same as the last time we looked
			if !dataflowBlockChanged[i] {
				continue
			}
			iterationChanged = true
			dataflowBlockChanged[i] = false
			value := dataflowBlockInitialStates[i]
			// Propogate dataflow forward through the instructions
			for j, ins := range b.Instrs {
				if r, ok := ins.(*ssa.RunDefers); ok {
					runDeferSets[r] = value
				}
				newValue, repeated := dataflowTransfer(b.Index, j, &ins, value)
				value = newValue
				anyRepeated = anyRepeated || repeated
			}
			for _, succ := range b.Succs {
				var sameAsA bool
				dataflowBlockInitialStates[succ.Index], sameAsA = stackSetUnion(dataflowBlockInitialStates[succ.Index], value)
				dataflowBlockChanged[succ.Index] = dataflowBlockChanged[succ.Index] || !sameAsA
			}
		}
		// Check if any change flag was set this iteration. If so we have more work to do
		if !iterationChanged {
			break
		}
	}

	if verbose {
		fmt.Printf("Fn: %s (%v)\n", fn.Name(), fn.Prog.Fset.PositionFor(fn.Pos(), false))
		for ins, stacks := range runDeferSets {
			fmt.Printf("Ins: %v (block %d), sets: %v\n", ins, ins.Block().Index, stacks)
			fmt.Printf("$sets %d\n", len(stacks))
			for _, stack := range stacks {
				fmt.Printf("$size %d\n", len(stack))
			}
			fmt.Printf("> %s", fn.Name())
			for _, stack := range stacks {
				fmt.Printf(" %d", len(stack))
			}
			fmt.Printf("\n")

		}
	}
	if anyRepeated {
		return DeferResults{false, runDeferSets}
	}
	return DeferResults{true, runDeferSets}
}

// Run the analysis on an entire program, and report the results to stdout
func AnalyzeDefer(program *ssa.Program, verbose bool) {
	functions := ssautil.AllFunctions(program)
	// Sort the functions so output is consistent between runs. AllFunctions should return a slice, not a go-style set
	sortedFunctions := []*ssa.Function{}
	for f := range functions {
		sortedFunctions = append(sortedFunctions, f)
	}
	sort.Slice(sortedFunctions, func(i int, j int) bool { return sortedFunctions[i].Name() < sortedFunctions[j].Name() })
	boundedFuncCount := 0
	for _, f := range sortedFunctions {
		results := AnalyzeFunctionDefers(f, verbose)
		if !results.DeferStackBounded {
			fmt.Printf("Unbounded defer stack in %s (%s, %v)\n", f.Name(), f.Pkg.Pkg.Name(), f.Prog.Fset.PositionFor(f.Pos(), false))
		} else {
			boundedFuncCount++
		}
	}
	fmt.Printf("%d functions had bounded defers\n", boundedFuncCount)
}
