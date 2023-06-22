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

// IMPLEMENTATION OF NEW INTERACE
type escapeAnalysisImpl struct {
	ProgramAnalysisState
}
type escapeContextImpl struct {
	g *EscapeGraph
	f *ssa.Function
}

var _ dataflow.EscapeCallsiteInfo = (*escapeCallsiteInfoImpl)(nil)

func (*escapeAnalysisImpl) IsEscapeAnalysisState2() bool { return true }

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
func InitializeEscapeAnalysisState2(state *dataflow.AnalyzerState) error {
	eaState, err := EscapeAnalysis(state, state.PointerAnalysis.CallGraph.Root)
	if err != nil {
		return err
	}
	state.EscapeAnalysisState = eaState
	state.EscapeAnalysisState2 = &escapeAnalysisImpl{*eaState}
	return nil
}

// IMPLEMENTATION OF OLD INTERFACE (SOON TO BE DEPRECATED):
// Implementations for the OldEscapeAnalysisState of the dataflow package
func (p *ProgramAnalysisState) IsEscapeAnalysisState() bool { return true }

func (p *ProgramAnalysisState) InitialGraphs() map[*ssa.Function]dataflow.EscapeGraph {
	m := map[*ssa.Function]dataflow.EscapeGraph{}
	for f, s := range p.summaries {
		m[f] = s.initialGraph
	}
	return m
}

// Compute the instruction locality for all instructions in f, assuming it is called from one of the callsites
// Callsite should contain the escape graph from f's perspective; such graphs can be generated using
// [EscapeGraph.ComputeCallsiteGraph], [EscapeGraph.Merge], and [EscapeGraph.ArbitraryCallerGraph] as necessary.
// In the returned map, a `true` value means the instruction is local, i.e. only manipulates memory that is proven to
// be local to the current goroutine. A `false` value means the instruction may read or write to memory cells that may
// be shared.
func (g *EscapeGraph) ComputeInstructionLocality(prog dataflow.OldEscapeAnalysisState,
	f *ssa.Function) map[ssa.Instruction]bool {
	p, ok := prog.(*ProgramAnalysisState)
	if !ok {
		panic("You should not have implemented the OldEscapeAnalysisState interface for another type.")
	}
	l, _ := computeInstructionLocality(p.summaries[f], g)
	return l
}

// ComputeCallsiteGraph computes the callsite graph from the perspective of `callee`, from the instruction `call` in
// `caller` when `caller` is called with context `g`.
// A particular call instruction can have multiple callee functions; a possible `g` must be supplied.
func (g *EscapeGraph) ComputeCallsiteGraph(prog dataflow.OldEscapeAnalysisState, caller *ssa.Function, call *ssa.Call,
	callee *ssa.Function) dataflow.EscapeGraph {
	//panic("unimplemented")
	p, ok := prog.(*ProgramAnalysisState)
	if !ok {
		panic("You should not have implemented the OldEscapeAnalysisState interface for another type.")
	}
	return ComputeArbitraryCallerGraph(callee, p)
	// TODO: actually compute this
	// Step 1: Run the normal convergence loop with the given context escape graph.
	// Step 2: read off the escape graph at the point just before the call
	// Step 3: Translate from caller to callee's context (rename from arguments to formal parameters).
}

// Computes the caller graph for a function, making no assumptions about the caller. This is useful if a function
// has no known caller or it can't be precisely determined. Use of this function may result in significantly fewer
// "local" values than using precise information from ComputeCallsiteGraph.
// (This graph is actually already computed; this function merely copies it.)
func (p *ProgramAnalysisState) ComputeArbitraryCallerGraph(f *ssa.Function) dataflow.EscapeGraph {
	return p.summaries[f].initialGraph.Clone()
}

// IClone is the interface version of Clone
func (g *EscapeGraph) IClone() dataflow.EscapeGraph {
	return g.Clone()
}

// IMerge is the interface version of Merge
func (g *EscapeGraph) IMerge(g2 dataflow.EscapeGraph) {
	g2p, ok := g2.(*EscapeGraph)
	if !ok {
		panic("You should not have implemented the EscapeGraph interface for another type.")
	}
	g.Merge(g2p)
}

// InitializeEscapeAnalysisState initializes the escape analysis' state inside the dataflow state
// Returns an error if an error is encountered during the escape analysis.
func InitializeEscapeAnalysisState(state *dataflow.AnalyzerState) error {
	eaState, err := EscapeAnalysis(state, state.PointerAnalysis.CallGraph.Root)
	if err != nil {
		return err
	}
	state.EscapeAnalysisState = eaState
	return nil
}
