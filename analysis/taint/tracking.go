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
	// Sinks maps the sink nodes to the source node from which the data flows
	// More precisely, Sinks[sink][source] <== data from source flows to sink
	Sinks map[FlowNode]map[FlowNode]bool

	// Escapes maps the instructions where data escapes, coming from the source instruction it maps to.
	// More precisely, Escapes[instr][source] <== data from source escapes the thread at instr
	Escapes map[ssa.Instruction]map[ssa.Instruction]df.EscapeRationale
}

// FlowNode represents a node in Flows.Sinks.
// This is very similar to dataflow.NodeWithTrace, except it is more easily comparable.
type FlowNode struct {
	// Instr is the SSA instruction of the node.
	Instr ssa.Instruction
	// Trace is a string representation of the trace of the node.
	Trace string
}

// NewFlows returns a new object to track taint flows and flows from source to escape locations
func NewFlows() *Flows {
	return &Flows{
		Sinks:   map[FlowNode]map[FlowNode]bool{},
		Escapes: map[ssa.Instruction]map[ssa.Instruction]df.EscapeRationale{},
	}
}

// NewFlowNode returns a new FlowNode from node's SSA instruction and trace.
func NewFlowNode(node df.NodeWithTrace) FlowNode {
	return FlowNode{
		Instr: df.Instr(node.Node),
		Trace: node.Trace.SummaryString(),
	}
}

// addNewPathCandidate adds a new path between a source and a sink if a path
// does not exist already.
// Returns true if it adds a new path.
func (m *Flows) addNewPathCandidate(source FlowNode, sink FlowNode) bool {
	if source.Instr == nil || sink.Instr == nil {
		return false
	}

	if _, ok := m.Sinks[sink]; !ok {
		m.Sinks[sink] = make(map[FlowNode]bool)
	}

	m.Sinks[sink][source] = true
	return true
}

func (m *Flows) addNewEscape(source df.NodeWithTrace, escapeInstr ssa.Instruction, rationale df.EscapeRationale) {
	if m.Escapes == nil {
		return
	}
	sourceInstr := df.Instr(source.Node)
	if escapeInstr != nil && sourceInstr != nil {
		if _, ok := m.Escapes[sourceInstr]; !ok {
			m.Escapes[sourceInstr] = make(map[ssa.Instruction]df.EscapeRationale)
		}
		m.Escapes[sourceInstr][escapeInstr] = rationale
	}
}

// Merge merges the flows from b into m.
//
// requires m.Sinks != nil && m.Escapes != nil
func (m *Flows) Merge(b *Flows) {
	for x, yb := range b.Sinks {
		ya, ina := m.Sinks[x]
		if ina {
			m.Sinks[x] = unionNodes(ya, yb)
		} else {
			m.Sinks[x] = yb
		}
	}
	for x, yb := range b.Escapes {
		ya, ina := m.Escapes[x]
		if ina {
			m.Escapes[x] = unionInstrs(ya, yb)
		} else {
			m.Escapes[x] = yb
		}
	}
}

// unionNodes is a utility function to merge two sets of nodes.
func unionNodes(p1 map[FlowNode]bool, p2 map[FlowNode]bool) map[FlowNode]bool {
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

// unionInstrs is a utility function to merge two sets of instructions.
func unionInstrs(p1 map[ssa.Instruction]df.EscapeRationale, p2 map[ssa.Instruction]df.EscapeRationale) map[ssa.Instruction]df.EscapeRationale {
	// NOTE this is a duplicate of unionNodes because the ssa.Instruction
	// interface does not implement the comparable constraint
	for x, yb := range p2 {
		ya, ina := p1[x]
		if ina {
			p1[x] = ya // preserve the value in p1
		} else {
			p1[x] = yb
		}
	}
	return p1
}

// Position returns the position of instr in program p and true if the position is valid.
// Returns an empty position and false if invalid.
func Position(p *ssa.Program, instr ssa.Instruction) (token.Position, bool) {
	pos := instr.Pos()
	file := p.Fset.File(pos)
	if pos != token.NoPos && file != nil {
		return file.Position(pos), true
	}

	return token.Position{}, false
}
