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
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// simpleDriver is a simple type to store the state for a simple traversal of the graph of blocks in the SSA
type simpleDriver struct {
	block      *ssa.BasicBlock          // the current block
	nextBlocks []*ssa.BasicBlock        // the queue of blocks to visit next
	visited    map[*ssa.BasicBlock]bool // the set of blocks that have been visited
}

// addNext adds the next block to visit if it has not been seen yet.
func (d *simpleDriver) addNext(block *ssa.BasicBlock) {
	if d.visited[block] {
		d.nextBlocks = append(d.nextBlocks, block)
	}
}

// RunDFS visits the blocks in the function in a depth-first search, running the instruction operation on every
// instruction in each Block.
func RunDFS(op InstrOp, function *ssa.Function) {
	if len(function.Blocks) == 0 {
		return
	}
	d := simpleDriver{
		block: function.Blocks[0],
		// Queue is at most as long as there are blocks in the function
		nextBlocks: make([]*ssa.BasicBlock, 0, len(function.Blocks)),
		visited:    make(map[*ssa.BasicBlock]bool),
	}
	d.addNext(d.block)
	for {
		// Set the current Block if there is one
		if len(d.nextBlocks) == 0 {
			return
		}
		d.block = d.nextBlocks[len(d.nextBlocks)-1]       // LIFO
		d.nextBlocks = d.nextBlocks[:len(d.nextBlocks)-1] // LIFO
		d.visited[d.block] = true
		// Iterate through instructions.
		for _, instr := range d.block.Instrs {
			InstrSwitch(op, instr)
		}
		for _, block := range d.block.Succs {
			d.addNext(block)
		}
	}
}

// PathSensitiveInstrOp is an InstrOp with additional functionality to indicate that the operation is running on
// a different path
type PathSensitiveInstrOp interface {
	InstrOp
	NewPath()                 // Called when a new path is inspected.
	EndPath()                 // Called when a path ended.
	NewBlock(*ssa.BasicBlock) // Called when a new Block is entered on a path.
}

// LastInstrIsReturn returns true when the last instruction of the block is a return instruction
func LastInstrIsReturn(block *ssa.BasicBlock) bool {
	n := len(block.Instrs)
	if n == 0 {
		return false
	}

	lastInstr := block.Instrs[n-1]
	_, ok := lastInstr.(*ssa.Return)
	return ok
}

// RunAllPaths tries every possible simple path in the function and runs the instruction operation calling NewPath
// every time a new path from the initial Block is taken, and NewBlock every time a new Block in a path is entered.
// The operation op should implement the functionality to keep track of path information, either at the Block level
// or at the operation level.
func RunAllPaths(op PathSensitiveInstrOp, function *ssa.Function) {
	if len(function.Blocks) == 0 {
		return
	}
	nextBlocks := make([]*BlockTree, 0, len(function.Blocks))

	// Start at the entry point
	t := &BlockTree{Block: function.Blocks[0], Parent: nil, Children: []*BlockTree{}}
	nextBlocks = append(nextBlocks, t)
	for {
		if len(nextBlocks) == 0 {
			return
		}
		// Pop
		cur := nextBlocks[len(nextBlocks)-1]
		nextBlocks = nextBlocks[:len(nextBlocks)-1] // LIFO
		added := false
		for _, block := range cur.Block.Succs {
			// If Block has not been visited more than once on that path
			if cur.CountPathOccurrences(block) <= 1 {
				child := cur.AddChild(block)
				nextBlocks = append(nextBlocks, child)
				added = true
			}
		}
		// Nothing added - this is a leaf node - execute operation on path if last Block returns
		if !added && LastInstrIsReturn(cur.Block) {
			op.NewPath()
			for _, block := range cur.PathToLeaf().ToBlocks() {
				op.NewBlock(block)
				for _, instruction := range block.Instrs {
					InstrSwitch(op, instruction)
				}
			}
			op.EndPath()
		}
	}
}

// IterativeAnalysis is an iterative analysis that extends an InstrOp with a function executed each time a
// new Block is visited, and a function that queries the analysis once the Block has been visited to check
// whether the analysis information has changed.
type IterativeAnalysis interface {
	InstrOp
	Pre(instruction ssa.Instruction)
	Post(instruction ssa.Instruction)
	NewBlock(block *ssa.BasicBlock)
	ChangedOnEndBlock() bool // ChangedOnEndBlock returns a boolean signaling the information has changed.
}

// RunForwardIterative visits the blocks in the function. At each Block visited, it queues the successors of the Block
// if the information for the Block has changed after visiting each of its instructions.
// All reachable blocks of the function will be visited if the call to ChangedOnBlock is true after each first visit
// to a given Block (the IterativeAnalysis structure must keep track of previously visited blocks, and ensure
// termination)
func RunForwardIterative(op IterativeAnalysis, function *ssa.Function) {
	if len(function.Blocks) == 0 {
		return
	}
	// Block indexes to visit next
	var worklist []*ssa.BasicBlock
	// memoize paths between blocks
	var pathMem map[*ssa.BasicBlock]map[*ssa.BasicBlock]bool
	worklist = append(worklist, function.Blocks[0])
	for { // until fixpoint is reached
		// Set the current Block if there is one
		if len(worklist) == 0 {
			return
		}
		block := worklist[0]
		worklist = worklist[1:]
		// Iterate through instructions.
		op.NewBlock(block)
		for _, instr := range block.Instrs {
			op.Pre(instr)
			InstrSwitch(op, instr)
			op.Post(instr)
		}
		if op.ChangedOnEndBlock() {
			for _, nextBlock := range function.Blocks {
				if HasPathTo(block, nextBlock, pathMem) {
					if !funcutil.Contains(worklist, nextBlock) {
						worklist = append(worklist, nextBlock)
					}
				}
			}
		}

	}
}
