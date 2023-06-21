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

// Package dataflow contains abstractions for reasoning about data flow within programs.
package dataflow

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// Visitor represents a visitor that runs a inter-procedural analysis from entrypoint.
type Visitor interface {
	Visit(s *AnalyzerState, entrypoint NodeWithTrace)
}

// CrossFunctionFlowGraph represents a inter-procedural data flow graph.
type CrossFunctionFlowGraph struct {
	// ForwardEdges represents edges between nodes belonging to different subgraphs (inter-procedural version of
	// (GraphNode).Out)
	ForwardEdges map[GraphNode]map[GraphNode]bool

	// BackwardEdges represents backward edges between nodes belonging to different subgraphs (inter-procedural
	// version of (GraphNode).In)
	BackwardEdges map[GraphNode]map[GraphNode]bool

	// Summaries maps the functions in the SSA to their summaries
	Summaries map[*ssa.Function]*SummaryGraph

	// AnalyzerState is a pointer to the analyzer state from which the dataflow graph is computed
	AnalyzerState *AnalyzerState

	// built indicates whether this graph has been built
	// this should only be set to true by BuildGraph() and be false by default
	built bool

	// Globals are edges between global nodes and the nodes that access the global
	Globals map[*GlobalNode]map[*AccessGlobalNode]bool
}

// NewCrossFunctionFlowGraph returns a new non-built cross function flow graph.
func NewCrossFunctionFlowGraph(summaries map[*ssa.Function]*SummaryGraph, state *AnalyzerState) CrossFunctionFlowGraph {
	return CrossFunctionFlowGraph{
		Summaries:     summaries,
		AnalyzerState: state,
		built:         false,
		ForwardEdges:  make(map[GraphNode]map[GraphNode]bool),
		BackwardEdges: make(map[GraphNode]map[GraphNode]bool),
	}
}

// IsBuilt returns true iff the cross function graph has been built, i.e. the summaries have been linked together.
func (g *CrossFunctionFlowGraph) IsBuilt() bool {
	return g.built
}

// Print prints each of the function summaries in the graph.
func (g *CrossFunctionFlowGraph) Print(w io.Writer) {
	fmt.Fprintf(w, "digraph program {\n")
	fmt.Fprintf(w, "\tcompound=true;\n") // visually group subgraphs together
	for _, summary := range g.Summaries {
		summary.Print(false, w)
	}
	const forwardColor = "\"#1cf4a3\""  // green
	const backwardColor = "\"#dc143c\"" // red
	const fmtColorEdge = "%s -> %s [color=%s];\n"
	for src, dsts := range g.ForwardEdges {
		for dst := range dsts {
			fmt.Fprintf(w, fmtColorEdge, escape(src.String()), escape(dst.String()), forwardColor)
		}
	}
	for dst, srcs := range g.BackwardEdges {
		for src := range srcs {
			fmt.Fprintf(w, fmtColorEdge, escape(dst.String()), escape(src.String()), backwardColor)
		}
	}

	for global, accesses := range g.Globals {
		for access := range accesses {
			// write is an edge from global <- access, read is an edge from global -> access
			if access.IsWrite {
				fmt.Fprintf(w, fmtColorEdge, escape(access.String()), escape(global.String()), forwardColor)
				fmt.Fprintf(w, fmtColorEdge, escape(global.String()), escape(access.String()), backwardColor)
			} else {
				fmt.Fprintf(w, fmtColorEdge, escape(global.String()), escape(access.String()), forwardColor)
				fmt.Fprintf(w, fmtColorEdge, escape(access.String()), escape(global.String()), backwardColor)
			}
		}
	}

	fmt.Fprintf(w, "}\n")
}

// InsertSummaries inserts all the summaries from g2 in g
func (g *CrossFunctionFlowGraph) InsertSummaries(g2 CrossFunctionFlowGraph) {
	for f, sum := range g2.Summaries {
		g.Summaries[f] = sum
	}
}

// KeyType is a value type to represents keys
type KeyType = string

// NodeWithTrace represents a GraphNode with two traces, a Trace for the call stack at the node and a ClosureTrace for
// the stack of makeClosure instructions at the node
type NodeWithTrace struct {
	Node         GraphNode
	Trace        *NodeTree[*CallNode]
	ClosureTrace *NodeTree[*ClosureNode]
}

// Key generates an object of type KeyType whose *value* identifies the value of g uniquely.
// If two NodeWithTrace objects represent the same node with the same call and closure traces, the Key() method
// will return the same value
func (g NodeWithTrace) Key() KeyType {
	s := g.Node.LongID() + "!" + g.Trace.Key() + "!" + g.ClosureTrace.Key()
	return s
}

// BuildGraph builds the cross function flow graph by connecting summaries together
func (g *CrossFunctionFlowGraph) BuildGraph(isEntrypoint func(*config.Config, ssa.Node) bool) {
	c := g.AnalyzerState
	logger := c.Logger

	logger.Infof("Building inter-procedural flow graph...")

	// Open a file to output summaries
	summariesFile := openSummaries(c)
	if summariesFile != nil {
		defer summariesFile.Close()
	}

	reachable := CallGraphReachable(g.AnalyzerState.PointerAnalysis.CallGraph, false, false)

	// Build the inter-procedural data flow graph: link all the summaries together
	for _, summary := range g.Summaries {
		if summary == nil {
			continue
		}
		if summariesFile != nil {
			_, _ = summariesFile.WriteString(fmt.Sprintf("%s:\n", summary.Parent.String()))
			summary.Print(false, summariesFile)
			_, _ = summariesFile.WriteString("\n")
		}

		// Interprocedural edges: callers to callees
		for _, callNodes := range summary.Callees {
			for _, node := range callNodes {
				if node.Callee() != nil && node.CalleeSummary == nil {
					var calleeSummary *SummaryGraph

					if node.callee.Type != InterfaceContract {
						calleeSummary = findCalleeSummary(node.Callee(), g.Summaries)
					}
					// If it's not in the generated summaries, try to fetch it from predefined summaries or interface
					// contracts, or build the summary
					if calleeSummary == nil {
						if calleeSummary = g.AnalyzerState.LoadExternalContractSummary(node); calleeSummary != nil {
							logger.Debugf("Loaded %s from external contracts.\n",
								node.CallSite().Common().String())
							g.Summaries[node.Callee()] = calleeSummary

						} else if calleeSummary = LoadPredefinedSummary(
							node.Callee(), GetUniqueFunctionId()); calleeSummary != nil {

							logger.Debugf("Loaded %s from summaries.\n", node.Callee().String())
							g.Summaries[node.Callee()] = calleeSummary

						} else if c.Config.SummarizeOnDemand && reachable[node.Callee()] && ShouldBuildSummary(c, node.Callee()) {

							logger.Debugf("Building summary for %v...\n", node.Callee())

							result, err := SingleFunctionAnalysis(c, node.Callee(), true, GetUniqueFunctionId(), isEntrypoint, nil)
							if err != nil {
								panic(fmt.Errorf("single function analysis failed for %v: %v", node.Callee(), err))
							}
							logger.Debugf("Finished building summary for %v (%.2f s)", node.Callee(), result.Time.Seconds())

							calleeSummary = result.Summary
							g.Summaries[node.Callee()] = calleeSummary
						}
					}
					// Add edge from callee to caller (adding a call site in the callee)
					if calleeSummary != nil {
						if x := calleeSummary.Callsites[node.CallSite()]; x == nil {
							calleeSummary.Callsites[node.CallSite()] = node
						}
					} else {
						summaryNotFound(g, node)
					}
					node.CalleeSummary = calleeSummary // nil is safe
				}
			}
		}

		// Interprocedural edges: closure creation to anonymous function
		for _, closureNode := range summary.CreatedClosures {
			if closureNode.instr != nil {
				closureSummary := findClosureSummary(closureNode.instr, g.Summaries)

				// Add edge from created closure summary to creator
				if closureSummary != nil {
					closureSummary.ReferringMakeClosures[closureNode.instr] = closureNode
				}
				closureNode.ClosureSummary = closureSummary // nil is safe
			}
		}

		// Interprocedural edges: bound variable to capturing anonymous function
		for _, boundLabelNode := range summary.BoundLabelNodes {
			if boundLabelNode.targetInfo.MakeClosure != nil {
				closureSummary := findClosureSummary(boundLabelNode.targetInfo.MakeClosure, g.Summaries)
				boundLabelNode.targetAnon = closureSummary // nil is safe
			}
		}
	}
	// Change the built flag to true
	g.built = true
}

func (g *CrossFunctionFlowGraph) RunCrossFunctionPass(visitor Visitor,
	isEntryPoint func(*config.Config, ssa.Node) bool) {
	var entryFuncs []*SummaryGraph
	var entryPoints []NodeWithTrace

	for _, summary := range g.Summaries {
		// Identify the entry points for that function: all the call sites that are entrypoints
		// and all the synthetic nodes in the function body.
		for _, snode := range summary.SyntheticNodes {
			entry := NodeWithTrace{Node: snode}
			entryPoints = append(entryPoints, entry)
		}
		if isEntryPoint(g.AnalyzerState.Config, summary.Parent) {
			entryFuncs = append(entryFuncs, summary)
		}
	}

	for _, summary := range entryFuncs {
		for _, node := range summary.Callsites {
			entry := NodeWithTrace{Node: node}
			entryPoints = append(entryPoints, entry)

			for _, arg := range node.args {
				entryPoints = append(entryPoints, NodeWithTrace{arg, nil, nil})
			}
		}
	}

	g.AnalyzerState.Logger.Debugf("--- # of analysis entrypoints: %d ---\n", len(entryPoints))

	// Run the analysis for every entrypoint. We may be able to change this to run the analysis for all entrypoints
	// at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack implements.
	for _, entry := range entryPoints {
		visitor.Visit(g.AnalyzerState, entry)
	}
}

// CrossFunctionPass runs the pass on the inter-procedural flow graph.
// Most of the logic is in visitor that is called for
// each possible source node identified.
//
// This function does nothing if there are no summaries
// (i.e. `len(g.summaries) == 0`)
// or if `cfg.SkipInterprocedural` is set to true.
func (g *CrossFunctionFlowGraph) CrossFunctionPass(c *AnalyzerState, visitor Visitor,
	isEntryPoint func(*config.Config, ssa.Node) bool) {
	// Skip the pass if user configuration demands it
	if c.Config.SkipInterprocedural || (!c.Config.SummarizeOnDemand && len(g.Summaries) == 0) {
		c.Logger.Infof("Skipping inter-procedural pass: config.SkipInterprocedural=%v, len(summaries)=%d\n",
			c.Config.SkipInterprocedural, len(g.Summaries))
		return
	}

	// Build the inter-procedural flow graph
	g.BuildGraph(isEntryPoint)

	// Open the coverage file if specified in configuration
	coverage := openCoverage(c)
	if coverage != nil {
		defer coverage.Close()
	}

	// Run the analysis
	g.RunCrossFunctionPass(visitor, isEntryPoint)
}

// VisitorNode represents a node in the inter-procedural dataflow graph to be visited.
type VisitorNode struct {
	NodeWithTrace
	ParamStack *ParamStack
	Prev       *VisitorNode
	Depth      int
}

// ParamStack represents a stack of parameters.
type ParamStack struct {
	Param *ParamNode
	Prev  *ParamStack
}

// Add adds p to the stack.
func (ps *ParamStack) Add(p *ParamNode) *ParamStack {
	return &ParamStack{Param: p, Prev: ps}
}

// Parent returns the previous param in the stack.
func (ps *ParamStack) Parent() *ParamStack {
	if ps == nil {
		return nil
	} else {
		return ps.Prev
	}
}

// findCalleeSummary returns the summary graph of callee in summaries if present. Returns nil if not.
func findCalleeSummary(callee *ssa.Function, summaries map[*ssa.Function]*SummaryGraph) *SummaryGraph {
	if summary, ok := summaries[callee]; ok {
		return summary
	}

	for summarized, summary := range summaries {
		// sometimes a "thunk" function will be the same as a normal function,
		// just with a different name ending in $thunk and the same position
		if (strings.HasPrefix(callee.String(), summarized.String()) ||
			strings.HasPrefix(summarized.String(), callee.String())) &&
			callee.Pos() == summarized.Pos() {
			return summary
		}
	}

	return nil
}

// findClosureSummary returns the summary graph of the function used in the MakeClosure instruction instr
func findClosureSummary(instr *ssa.MakeClosure, summaries map[*ssa.Function]*SummaryGraph) *SummaryGraph {
	switch funcValue := instr.Fn.(type) {
	case *ssa.Function:
		if summary, ok := summaries[funcValue]; ok {
			return summary
		} else {
			return nil
		}
	default:
		return nil
	}
}

// IsSourceFunction returns true if cfg identifies f as a source.
func IsSourceFunction(cfg *config.Config, f *ssa.Function) bool {
	pkg := lang.PackageNameFromFunction(f)
	return cfg.IsSource(config.CodeIdentifier{Package: pkg, Method: f.Name()})
}

func summaryNotFound(g *CrossFunctionFlowGraph, node *CallNode) {
	if node.callee.Callee.Name() != "init" &&
		g.AnalyzerState.IsReachableFunction(node.callee.Callee) {

		g.AnalyzerState.Logger.Debugf("Could not find summary of %s", node.callSite.String())
		if node.callee.Callee != nil {
			g.AnalyzerState.Logger.Debugf("|-- Key: %s", node.callee.Callee.String())
		}
		g.AnalyzerState.Logger.Debugf("|-- Location: %s", node.Position(g.AnalyzerState))

		if node.callSite.Common().IsInvoke() {
			g.AnalyzerState.Logger.Debugf("|-- invoke resolved to callee %s", node.callee.Callee.String())
		}
	}
}

// openCoverage opens the coverage file, if the config requires it.
// the caller is responsible for closing the file if non-nil
func openCoverage(c *AnalyzerState) *os.File {
	var err error
	var coverage *os.File

	if c.Config.ReportCoverage {
		coverage, err = os.CreateTemp(c.Config.ReportsDir, "coverage-*.out")
		if err != nil {
			coverage = nil
			c.Logger.Warnf("Could not create coverage file, continuing.\n")
			c.Logger.Warnf("Error was: %s", err)
		} else {
			c.Logger.Infof("Writing coverage information in %s.\n", coverage.Name())
			_, _ = coverage.WriteString("mode: set\n")
		}
	}
	return coverage
}

// openSummaries returns a non-nil opened file if the configuration is set properly
// the caller is responsible for closing the file if non-nil
func openSummaries(c *AnalyzerState) *os.File {
	var err error
	var summariesFile *os.File

	if c.Config.ReportSummaries {
		summariesFile, err = os.CreateTemp(c.Config.ReportsDir, "summaries-*.out")
		if err != nil {
			summariesFile = nil
			c.Logger.Warnf("Could not create summaries files, continuing.\n")
			c.Logger.Warnf("Error was: %s", err)
		} else {
			c.Logger.Infof("Writing summaries in %s.\n", summariesFile.Name())
		}
	}
	return summariesFile
}

// UnwindCallstackFromCallee returns the CallNode that should be returned upon. It satisfies the following conditions:
// - the CallNode is in the callsites set
// - the CallNode is in the trace
// If no CallNode satisfies these conditions, nil is returned.
func UnwindCallstackFromCallee(callsites map[ssa.CallInstruction]*CallNode, trace *NodeTree[*CallNode]) *CallNode {
	// no trace = nowhere to return to.
	if trace == nil {
		return nil
	}

	// the number of callsites in a call is expected to be small
	for _, x := range callsites {
		if x.CallSite() == trace.Label.CallSite() && x.Callee() == trace.Label.Callee() {
			return x
		}
	}
	// no return node has been found
	return nil
}

// BuildSummary builds a summary for function and adds it to s's flow graph.
func BuildSummary(s *AnalyzerState, function *ssa.Function, isEntrypoint func(*config.Config, ssa.Node) bool) *SummaryGraph {
	summary := buildSummary(s, function, isEntrypoint)
	s.FlowGraph.Summaries[function] = summary

	return summary
}

// buildSummary builds a summary for function and returns it.
func buildSummary(s *AnalyzerState, function *ssa.Function, isEntrypoint func(*config.Config, ssa.Node) bool) *SummaryGraph {
	if summary, ok := s.FlowGraph.Summaries[function]; ok {
		return summary
	}

	logger := s.Logger
	id := GetUniqueFunctionId()
	summary := LoadPredefinedSummary(function, id)
	if summary != nil {
		logger.Debugf("\tLoaded pre-defined summary for %v\n", function)
	} else {
		logger.Debugf("\tBuilding summary for %v...\n", function)
		result, err := SingleFunctionAnalysis(s, function, true, id, isEntrypoint, nil)

		if err != nil {
			panic(fmt.Errorf("single function analysis failed for %v: %v", function, err))
		}

		logger.Debugf("\tFinished building summary for %v (%.2f s)", function, result.Time.Seconds())
		summary = result.Summary
	}

	return summary
}

// BuildSummariesFromCallgraph builds summaries for all the reachable callees of n
// corresponding to n's trace.
func BuildSummariesFromCallgraph(s *AnalyzerState, n NodeWithTrace, isEntrypoint func(*config.Config, ssa.Node) bool) {
	node := s.PointerAnalysis.CallGraph.Nodes[n.Node.Graph().Parent]
	functions := []*ssa.Function{}
	for _, in := range node.In {
		callSite := in.Site
		if n.Trace == nil || (callSite == n.Trace.Label.CallSite() && in.Callee.Func == n.Trace.Label.Callee()) {
			createdSummary, ok := s.FlowGraph.Summaries[callSite.Parent()]
			// build a summary for the callsite's parent if:
			// - it is present in the flowgraph but not constructed, or
			// - it is not present in the flowgraph, reachable, and a summary should be built for it
			if (ok && !createdSummary.Constructed) || (!ok && s.IsReachableFunction(callSite.Parent()) && ShouldBuildSummary(s, callSite.Parent())) {
				functions = append(functions, callSite.Parent())
			}
		}
	}

	type sf struct {
		s *SummaryGraph
		f *ssa.Function
	}
	f := func(fn *ssa.Function) sf {
		return sf{s: buildSummary(s, fn, isEntrypoint), f: fn}
	}
	summaries := funcutil.MapParallel(functions, f, runtime.NumCPU())

	for _, sf := range summaries {
		s.FlowGraph.Summaries[sf.f] = sf.s
	}

	s.FlowGraph.BuildGraph(isEntrypoint)
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
func addNext(c *AnalyzerState,
	que []*VisitorNode,
	seen map[NodeWithTrace]bool,
	cur *VisitorNode,
	node GraphNode,
	trace *NodeTree[*CallNode],
	closureTrace *NodeTree[*ClosureNode]) []*VisitorNode {

	newNode := NodeWithTrace{Node: node, Trace: trace, ClosureTrace: closureTrace}

	// Stop conditions: node is already in seen, trace is a lasso or depth exceeds limit
	if seen[newNode] || trace.IsLasso() || cur.Depth > c.Config.MaxDepth {
		return que
	}

	// logic for parameter stack
	pStack := cur.ParamStack
	switch curNode := cur.Node.(type) {
	case *ReturnValNode:
		pStack = pStack.Parent()
	case *ParamNode:
		pStack = pStack.Add(curNode)
	}

	newVis := &VisitorNode{
		NodeWithTrace: newNode,
		ParamStack:    pStack,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	que = append(que, newVis)
	seen[newNode] = true
	return que
}
