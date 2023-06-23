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

package taint

import (
	"go/token"

	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

// Flows stores information about where the data coming from specific instructions flows to.
type Flows struct {
	// Sinks maps the sink instructions to the source instruction from which the data flows
	// More precisely, Sinks[sink][source] <== data from source flows to sink
	Sinks map[ssa.Instruction]map[ssa.Instruction]bool

	// Escapes maps the instructions where data escapes, coming from the source instruction it maps to.
	// More precisely, Escapes[instr][source] <== data from source escapes the thread at instr
	Escapes map[ssa.Instruction]map[ssa.Instruction]bool
}

type PositionSetMap = map[token.Position]map[token.Position]bool

// NewFlows returns a new object to track taint flows and flows from source to escape locations
func NewFlows() *Flows {
	return &Flows{
		Sinks:   map[ssa.Instruction]map[ssa.Instruction]bool{},
		Escapes: map[ssa.Instruction]map[ssa.Instruction]bool{},
	}
}

// addNewPathCandidate adds a new path between a source and a sink to paths using the information in elt
// returns true if it adds a new path.
// @requires elt.Node.IsSink()
func (m *Flows) addNewPathCandidate(source df.GraphNode, sink df.GraphNode) bool {
	var sourceInstr ssa.Instruction
	var sinkInstr ssa.CallInstruction

	// The source instruction depends on the type of the source: a call node or synthetic node are directly
	// related to an instruction, whereas the instruction of a call node argument is the instruction of its
	// parent call node.
	switch node := source.(type) {
	case *df.CallNode:
		sourceInstr = node.CallSite()
	case *df.CallNodeArg:
		sourceInstr = node.ParentNode().CallSite()
	case *df.SyntheticNode:
		sourceInstr = node.Instr()
	}

	// Similar thing for the sink. Synthetic nodes are currently not used as potential sinks.
	switch node := sink.(type) {
	case *df.CallNode:
		sinkInstr = node.CallSite()
	case *df.CallNodeArg:
		sinkInstr = node.ParentNode().CallSite()
	}

	if sinkInstr != nil && sourceInstr != nil {
		if _, ok := m.Sinks[sinkInstr.(ssa.Instruction)]; !ok {
			m.Sinks[sinkInstr.(ssa.Instruction)] = make(map[ssa.Instruction]bool)
		}
		m.Sinks[sinkInstr.(ssa.Instruction)][sourceInstr] = true
		return true
	}
	return false
}

func (m *Flows) addNewEscape(source df.GraphNode, escapeInstr ssa.Instruction) {
	var sourceInstr ssa.Instruction

	// The source instruction depends on the type of the source: a call node or synthetic node are directly
	// related to an instruction, whereas the instruction of a call node argument is the instruction of its
	// parent call node.
	switch node := source.(type) {
	case *df.CallNode:
		sourceInstr = node.CallSite()
	case *df.CallNodeArg:
		sourceInstr = node.ParentNode().CallSite()
	case *df.SyntheticNode:
		sourceInstr = node.Instr()
	}

	if escapeInstr != nil && sourceInstr != nil {
		if _, ok := m.Escapes[escapeInstr.(ssa.Instruction)]; !ok {
			m.Escapes[escapeInstr.(ssa.Instruction)] = make(map[ssa.Instruction]bool)
		}
		m.Escapes[escapeInstr.(ssa.Instruction)][sourceInstr] = true
	}
}

// Merge merges the flows from b into a
// requires a != nil
func (m *Flows) Merge(b *Flows) {
	for x, yb := range b.Sinks {
		ya, ina := m.Sinks[x]
		if ina {
			m.Sinks[x] = unionPaths(ya, yb)
		} else {
			m.Sinks[x] = yb
		}
	}
	for x, yb := range b.Escapes {
		ya, ina := m.Escapes[x]
		if ina {
			m.Escapes[x] = unionPaths(ya, yb)
		} else {
			m.Escapes[x] = yb
		}
	}
}

// unionPaths is a utility function to merge two sets of instructions.
func unionPaths(p1 map[ssa.Instruction]bool, p2 map[ssa.Instruction]bool) map[ssa.Instruction]bool {
	for x, yb := range p2 {
		ya, ina := p1[x]
		if ina {
			p1[x] = yb || ya
		} else {
			p1[x] = yb
		}
	}
	return p1
}

// ToPositions translates Flows into two sets of position maps, the first set being the set of sinks positions reached
// by source positions, and the second set being the set of escaped positions reached by source positions.
func (m *Flows) ToPositions(prog *ssa.Program) (PositionSetMap, PositionSetMap) {
	return instrPSetToPositionSetMap(prog, m.Sinks), instrPSetToPositionSetMap(prog, m.Escapes)
}

// instrPSetToPositionSetMap converts the map of sets of instructions to a map of sets of positions using the program
// prog to resolve the positions
func instrPSetToPositionSetMap(p *ssa.Program, iMap map[ssa.Instruction]map[ssa.Instruction]bool) PositionSetMap {
	pMap := make(PositionSetMap)

	for sinkNode, sourceNodes := range iMap {
		sinkPos := sinkNode.Pos()
		sinkFile := p.Fset.File(sinkPos)
		if sinkPos != token.NoPos && sinkFile != nil {
			pMap[sinkFile.Position(sinkPos)] = map[token.Position]bool{}
			for sourceNode := range sourceNodes {
				sourcePos := sourceNode.Pos()
				sourceFile := p.Fset.File(sourcePos)
				if sinkPos != token.NoPos && sourceFile != nil {
					pMap[sinkFile.Position(sinkPos)][sourceFile.Position(sourcePos)] = true
				}
			}
		}
	}
	return pMap
}
