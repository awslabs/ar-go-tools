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
	"github.com/awslabs/argot/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

// Implemenations for the EscapeAnalysisState of the dataflow package

func (e *ProgramAnalysisState) IsEscapeAnalysisState() bool { return true }

func (e *ProgramAnalysisState) InitialGraphs() map[*ssa.Function]dataflow.EscapeGraph {
	m := map[*ssa.Function]dataflow.EscapeGraph{}
	for f, s := range e.summaries {
		m[f] = s.initialGraph
	}
	return m
}

// Implements the EscapeGraph interface of the dataflow package

// Compute the instruction locality for all instructions in f, assuming it is called from one of the callsites
// Callsite should contain the escape graph from f's perspective; such graphs can be generated using
// [EscapeGraph.ComputeCallsiteGraph], [EscapeGraph.Merge], and [EscapeGraph.ArbitraryCallerGraph] as necessary.
// In the returned map, a `true` value means the instruction is local, i.e. only manipulates memory that is proven to
// be local to the current goroutine. A `false` value means the instruction may read or write to memory cells that may
// be shared.
func (g *EscapeGraph) ComputeInstructionLocality(prog dataflow.EscapeAnalysisState,
	f *ssa.Function) map[ssa.Instruction]bool {
	p, ok := prog.(*ProgramAnalysisState)
	if !ok {
		panic("You should not have implemented the EscapeAnalysisState interface for another type.")
	}
	return computeInstructionLocality(p.summaries[f], g)
}

// ComputeCallsiteGraph computes the callsite graph from the perspective of `callee`, from the instruction `call` in
// `caller` when `caller` is called with context `g`.
// A particular call instruction can have multiple callee functions; a possible `g` must be supplied.
func (g *EscapeGraph) ComputeCallsiteGraph(prog dataflow.EscapeAnalysisState, caller *ssa.Function, call *ssa.Call,
	callee *ssa.Function) dataflow.EscapeGraph {
	panic("unimplemented")
	//return ComputeArbitraryCallerGraph(callee, prog)
	// TODO: actually compute this
	// Step 1: Run the normal convergence loop with the given context escape graph.
	// Step 2: read off the escape graph at the point just before the call
	// Step 3: Translate from caller to callee's context (rename from arguments to formal parameters).
}

// Computes the caller graph for a function, making no assumptions about the caller. This is useful if a function
// has no known caller or it can't be precisely determined. Use of this function may result in significantly fewer
// "local" values than using precise information from ComputeCallsiteGraph.
// (This graph is actually already computed; this function merely copies it.)
func (g *EscapeGraph) ComputeArbitraryCallerGraph(prog dataflow.EscapeAnalysisState,
	f *ssa.Function) dataflow.EscapeGraph {
	p, ok := prog.(*ProgramAnalysisState)
	if !ok {
		panic("You should not have implemented the EscapeAnalysisState interface for another type.")
	}
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
