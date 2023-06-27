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

package escape

import (
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// Implementation of EscapeAnalysisState and related types
type escapeAnalysisImpl struct {
	ProgramAnalysisState
}
type escapeContextImpl struct {
	g *EscapeGraph
	f *ssa.Function
}

// Check types correspond to interfaces
var _ dataflow.EscapeAnalysisState = (*escapeAnalysisImpl)(nil)
var _ dataflow.EscapeCallsiteInfo = (*escapeCallsiteInfoImpl)(nil)
var _ dataflow.EscapeCallContext = (*escapeContextImpl)(nil)

func (*escapeAnalysisImpl) IsEscapeAnalysisState() bool { return true }

func (e *escapeAnalysisImpl) IsSummarized(f *ssa.Function) bool { return e.summaries[f] != nil }

func (p *escapeAnalysisImpl) ComputeArbitraryContext(f *ssa.Function) dataflow.EscapeCallContext {
	return &escapeContextImpl{p.summaries[f].initialGraph.Clone(), f}
}

func (p *escapeAnalysisImpl) ComputeInstructionLocalityAndCallsites(f *ssa.Function, ctx dataflow.EscapeCallContext) (
	instructionLocality map[ssa.Instruction]bool,
	callsiteInfo map[*ssa.Call]dataflow.EscapeCallsiteInfo) {
	c, ok := ctx.(*escapeContextImpl)
	if !ok {
		panic("You should not have implemented the EscapeCallContext interface for another type.")
	}
	if f != c.f {
		panic("Cannot compute locality of function with a different function's EscapeCallContext")
	}
	locality, callsites := computeInstructionLocality(p.summaries[f], c.g)
	callsiteInfo = map[*ssa.Call]dataflow.EscapeCallsiteInfo{}
	for k, v := range callsites {
		callsiteInfo[k] = &escapeCallsiteInfoImpl{v.g, v.callsite, v.nodes, v.prog}
	}
	return locality, callsiteInfo
}

func (c *escapeCallsiteInfoImpl) Resolve(callee *ssa.Function) dataflow.EscapeCallContext {
	calleeSummary, ok := c.prog.summaries[callee]
	if !ok {
		panic("Cannot resolve escape context for unsummarized function")
	}
	nodes := calleeSummary.nodes
	g := NewEmptyEscapeGraph(calleeSummary.nodes)
	// Copy over nodes into g that are reachable from the arguments.
	if len(callee.Params) != len(c.callsite.Call.Args) {
		panic("Argument mismatch")
	}
	mappedNodes := map[*Node]bool{}
	var mapNode func(*Node, *Node)

	// Map all nodes reachable from caller into g, assuming callerNode is represented by inner in g.
	// For argument/parameter nodes, these will be distinct, but their pointees (representing heap objects)
	// will be the same exact Nodes.
	mapNode = func(callerNode *Node, inner *Node) {
		g.status[inner] = c.g.status[callerNode]
		for pointee, isInternal := range c.g.edges[callerNode] {
			nodes.AddForeignNode(pointee)
			g.AddEdge(inner, pointee, isInternal)
			if !mappedNodes[pointee] {
				mappedNodes[pointee] = true
				mapNode(pointee, pointee)
			}
		}
	}

	for i, arg := range c.callsite.Call.Args {
		if lang.IsNillableType(arg.Type()) {
			mapNode(c.nodes.ValueNode(arg), nodes.ValueNode(callee.Params[i]))
		}
	}
	// TODO: freevars should be copied from the object representing the closure object
	return &escapeContextImpl{g, callee}
}

func (e *escapeContextImpl) Matches(other dataflow.EscapeCallContext) bool {
	o, ok := other.(*escapeContextImpl)
	if !ok {
		panic("You should not have implemented the EscapeCallContext interface for another type.")
	}
	if e.f != o.f { // misuse resistance
		panic("Cannot compare EscapeCallContexts of different functions")
	}
	return e.g.Matches(o.g)
}

func (e *escapeContextImpl) Merge(other dataflow.EscapeCallContext) (changed bool, merge dataflow.EscapeCallContext) {
	o, ok := other.(*escapeContextImpl)
	if !ok {
		panic("You should not have implemented the EscapeCallContext interface for another type.")
	}
	if e.f != o.f { // misuse resistance
		panic("Cannot merge EscapeCallContexts of different functions")
	}
	g := e.g.Clone()
	g.Merge(o.g)
	if g.Matches(e.g) {
		return false, e
	}
	return true, &escapeContextImpl{g, e.f}
}

// InitializeEscapeAnalysisState initializes the escape analysis' state inside the dataflow state
// Returns an error if an error is encountered during the escape analysis.
func InitializeEscapeAnalysisState(state *dataflow.AnalyzerState) error {
	eaState, err := EscapeAnalysis(state, state.PointerAnalysis.CallGraph.Root)
	if err != nil {
		return err
	}
	state.EscapeAnalysisState = &escapeAnalysisImpl{*eaState}
	return nil
}
