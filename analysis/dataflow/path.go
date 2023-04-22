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
	"strings"

	"github.com/awslabs/argot/analysis/lang"
	. "github.com/awslabs/argot/analysis/utils"
	"golang.org/x/tools/go/ssa"
)

// Condition hold information about a conditional path. If Positive, then the branch is the then-branch where
// the condition is the Value. If it is not Positive, then this refers to the else-branch
type Condition struct {
	// Positive indicates whether the branch is the then- or -else branch, i.e. the condition must be taken postively
	// or negatively
	Positive bool

	// Value refers to the value of the condition in the branching
	Value ssa.Value
}

func (c Condition) String() string {
	if c.Value == nil {
		return "nil"
	}
	if c.Positive {
		return c.Value.String()
	} else {
		return "not " + c.Value.String()
	}
}

// IsPredicateTo returns true when the condition is a predicate that applies to v
// The logic behind the statement "a predicate that applies to v" must match the expectations of the dataflow analysis
// Currently:
//   - the condition must be a call to some predicate (a function returning a boolean)
//     Possible extensions would include computing the expression of the boolean condition, which would allow more
//     general patterns like checking that a returned error is non-nil
//   - v must hold the same data as one of the arguments of the call
//     The logic for "same data" is in the ValuesWithSameData function of the lang package.
func (c Condition) IsPredicateTo(v ssa.Value) bool {
	if c.Value == nil {
		return false
	}
	vset := lang.ValuesWithSameData(v)
	switch x := c.Value.(type) {
	case *ssa.Call:
		if x.Call.IsInvoke() {
			sig := x.Call.Method.Type()
			if sig, ok := sig.Underlying().(*types.Signature); ok {
				if lang.IsPredicateFunctionType(sig) {
					for _, arg := range x.Call.Args {
						for same := range lang.ValuesWithSameData(arg) {
							if vset[same] {
								return true
							}
						}
					}
				}
			}
		} else {
			sig := x.Call.Value.Type()
			if sig, ok := sig.Underlying().(*types.Signature); ok {
				if lang.IsPredicateFunctionType(sig) {
					for _, arg := range x.Call.Args {
						if vset[arg] {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// ConditionInfo holds information about the conditions under which an object may be relevant.
type ConditionInfo struct {
	// If Satisfiable is false, the condition info refers to an object that cannot exist
	Satisfiable bool

	// Conditions is the list of conditions in the info, which can be empty even when Satisfiable is true
	// Should be interpreted as a conjunction of its elements.
	Conditions []Condition
}

func (c ConditionInfo) String() string {
	if !c.Satisfiable {
		return "false"
	}
	if len(c.Conditions) > 0 {
		return "cond: " + strings.Join(Map(c.Conditions, func(c Condition) string { return c.String() }), " && ")
	}
	return "satisfiable"
}

// AsPredicateTo filters the conditions in c that relate to the value v.
// The returned ConditionInfo is weaker than the input.
func (c ConditionInfo) AsPredicateTo(v ssa.Value) ConditionInfo {
	c2 := ConditionInfo{
		Satisfiable: c.Satisfiable,
		Conditions:  []Condition{},
	}
	for _, cond := range c.Conditions {
		if cond.IsPredicateTo(v) {
			c2.Conditions = append(c2.Conditions, cond)
		}
	}
	return c2
}

// PathInformation contains information about a path in the program. The object reflects a path in the program only if
// ConditionInfo.Satisfiable is true.
type PathInformation struct {
	// Blocks is the list of basic blocks in the path
	Blocks []*ssa.BasicBlock

	// Instructions is the list of instruction in the path
	Instructions []ssa.Instruction

	// Cond is a summary of some conditions that must be satisfied along the path. If the PathInformation refers to a
	// path that does not exist, then Cond.Satisfiable will be false.
	Cond ConditionInfo
}

func NonExistentPath() PathInformation {
	return PathInformation{Cond: ConditionInfo{Satisfiable: false}}
}

// FindIntraProceduralPath returns a path between the begin and end instructions.
// Returns nil if there is no path between being and end inside the function.
func FindIntraProceduralPath(begin ssa.Instruction, end ssa.Instruction) PathInformation {
	// Return nil if the parent functions of begin and end are different
	if begin.Parent() != end.Parent() {
		return NonExistentPath()
	}

	if begin.Block() != end.Block() {
		blockPath := FindPathBetweenBlocks(begin.Block(), end.Block())

		if blockPath == nil {
			return NonExistentPath()
		} else {
			var path []ssa.Instruction

			path = append(path, InstructionsBetween(begin.Block(), begin, lang.LastInstr(begin.Block()))...)
			for _, block := range blockPath[1 : len(blockPath)-1] {
				path = append(path, block.Instrs...)
			}
			path = append(path, InstructionsBetween(end.Block(), lang.FirstInstr(end.Block()), end)...)
			return PathInformation{
				Blocks:       blockPath,
				Instructions: path,
				Cond:         SimplePathCondition(blockPath),
			}
		}
	} else {
		instrs := InstructionsBetween(begin.Block(), begin, end)
		return PathInformation{
			Blocks:       []*ssa.BasicBlock{begin.Block()},
			Instructions: instrs,
			Cond:         ConditionInfo{Satisfiable: instrs != nil},
		}
	}
}

// SimplePathCondition returns the ConditionInfo that aggregates all conditions encountered on the path represented by
// the list of basic blocks. The input list of basic block must represent a program path (i.e. each basic block is
// one of the Succs of its predecessor).
func SimplePathCondition(blocks []*ssa.BasicBlock) ConditionInfo {
	var conditions []Condition

	for i, block := range blocks {
		if i < len(blocks)-1 {
			last := lang.LastInstr(block)
			if last != nil {
				switch branching := last.(type) {
				case *ssa.If:
					if blocks[i+1].Index == block.Succs[0].Index {
						conditions = append(conditions, Condition{Positive: true, Value: branching.Cond})
					} else if blocks[i+1].Index == block.Succs[1].Index {
						conditions = append(conditions, Condition{Positive: false, Value: branching.Cond})
					}
				}
			}
		}
	}
	return ConditionInfo{Satisfiable: true, Conditions: conditions}
}

// InstructionsBetween returns the instructions between begin and end in the block.
// If begin and end are not two instructions that appear in the same block and being appears before end, then
// the function returns nil.
func InstructionsBetween(block *ssa.BasicBlock, begin ssa.Instruction, end ssa.Instruction) []ssa.Instruction {
	flag := false
	var path []ssa.Instruction
	for _, instr := range block.Instrs {
		if instr == begin {
			flag = true
		}
		if flag {
			path = append(path, instr) // type cast cannot fail
		}
		if flag && instr == end {
			return path
		}
	}
	return nil
}

// FindPathBetweenBlocks is a BFS of the blocks successor graph returns a list of block indexes representing a path
// from begin to end. Returns nil iff there is no such path.
func FindPathBetweenBlocks(begin *ssa.BasicBlock, end *ssa.BasicBlock) []*ssa.BasicBlock {
	visited := make(map[*ssa.BasicBlock]int)
	t := &lang.BlockTree{Block: begin, Parent: nil, Children: []*lang.BlockTree{}}
	queue := []*lang.BlockTree{t}
	// BFS - optimize?
	for {
		if len(queue) == 0 {
			return nil
		} else {
			cur := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			visited[cur.Block] = 1
			if cur.Block == end {
				return cur.PathToLeaf().ToBlocks()
			}
			for _, block := range cur.Block.Succs {
				if _, ok := visited[block]; !ok {
					child := cur.AddChild(block)
					queue = append(queue, child)
				}
			}
		}
	}
}
