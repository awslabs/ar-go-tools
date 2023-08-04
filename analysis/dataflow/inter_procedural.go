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

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// Visitor represents a visitor that runs an inter-procedural analysis from entrypoint.
type Visitor interface {
	Visit(s *AnalyzerState, entrypoint NodeWithTrace)
}

// InterProceduralFlowGraph represents an inter-procedural data flow graph.
type InterProceduralFlowGraph struct {
	// ForwardEdges represents edges between nodes belonging to different sub-graphs (inter-procedural version of
	// (GraphNode).Out)
	ForwardEdges map[GraphNode]map[GraphNode]bool

	// BackwardEdges represents backward edges between nodes belonging to different sub-graphs (inter-procedural
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

// NewInterProceduralFlowGraph returns a new non-built cross function flow graph.
func NewInterProceduralFlowGraph(summaries map[*ssa.Function]*SummaryGraph, state *AnalyzerState) InterProceduralFlowGraph {
	return InterProceduralFlowGraph{
		Summaries:     summaries,
		AnalyzerState: state,
		built:         false,
		ForwardEdges:  make(map[GraphNode]map[GraphNode]bool),
		BackwardEdges: make(map[GraphNode]map[GraphNode]bool),
	}
}

// IsBuilt returns true iff the cross function graph has been built, i.e. the summaries have been linked together.
func (g *InterProceduralFlowGraph) IsBuilt() bool {
	return g.built
}

// Print prints each of the function summaries in the graph.
func (g *InterProceduralFlowGraph) Print(w io.Writer) {
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
			fmt.Fprintf(w, fmtColorEdge, escapeString(src.String()), escapeString(dst.String()), forwardColor)
		}
	}
	for dst, srcs := range g.BackwardEdges {
		for src := range srcs {
			fmt.Fprintf(w, fmtColorEdge, escapeString(dst.String()), escapeString(src.String()), backwardColor)
		}
	}

	for global, accesses := range g.Globals {
		for access := range accesses {
			// write is an edge from global <- access, read is an edge from global -> access
			if access.IsWrite {
				fmt.Fprintf(w, fmtColorEdge, escapeString(access.String()), escapeString(global.String()), forwardColor)
				fmt.Fprintf(w, fmtColorEdge, escapeString(global.String()), escapeString(access.String()), backwardColor)
			} else {
				fmt.Fprintf(w, fmtColorEdge, escapeString(global.String()), escapeString(access.String()), forwardColor)
				fmt.Fprintf(w, fmtColorEdge, escapeString(access.String()), escapeString(global.String()), backwardColor)
			}
		}
	}

	fmt.Fprintf(w, "}\n")
}

// InsertSummaries inserts all the summaries from g2 in g
func (g *InterProceduralFlowGraph) InsertSummaries(g2 InterProceduralFlowGraph) {
	for f, sum := range g2.Summaries {
		g.Summaries[f] = sum
	}
}

// BuildGraph builds the cross function flow graph by connecting summaries together
//
//gocyclo:ignore
func (g *InterProceduralFlowGraph) BuildGraph(isEntrypoint func(*config.Config, ssa.Node) bool) {
	c := g.AnalyzerState
	logger := c.Logger

	logger.Infof("Building inter-procedural flow graph...")

	// Open a file to output summaries
	summariesFile := openSummaries(c)
	if summariesFile != nil {
		defer summariesFile.Close()
	}

	// Build the inter-procedural data flow graph:
	nameAliases := map[string]*ssa.Function{}
	// STEP 1: build a map from full function names to summaries
	for summarized := range g.Summaries {
		// sometimes a "thunk" function will be the same as a normal function,
		// just with a different name ending in $thunk and the same position
		nameAliases[summarized.String()] = summarized
	}
	// STEP 2: Enforce dataflow contracts
	for _, summary := range g.Summaries {
		if summary == nil {
			continue
		}
		for _, callNodes := range summary.Callees {
			for _, node := range callNodes {
				if node.Callee() != nil && node.CalleeSummary == nil {
					if externalContractSummary := g.AnalyzerState.LoadExternalContractSummary(node); externalContractSummary != nil {
						logger.Debugf("Loaded %s from external contracts.\n",
							node.CallSite().Common().String())
						g.Summaries[node.Callee()] = externalContractSummary
						node.CalleeSummary = externalContractSummary
						if x := externalContractSummary.Callsites[node.CallSite()]; x == nil {
							externalContractSummary.Callsites[node.CallSite()] = node
						}
					}
				}
			}
		}
	}

	// STEP 3: link all the summaries together
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
				if node.Callee() != nil && node.CalleeSummary == nil &&
					g.AnalyzerState.IsReachableFunction(node.Callee()) {
					node.CalleeSummary = g.resolveCalleeSummary(node, nameAliases, isEntrypoint)
				}
			}
		}

		// Interprocedural edges: closure creation to anonymous function
		for _, closureNode := range summary.CreatedClosures {
			if closureNode.instr != nil {
				closureSummary := g.findClosureSummary(closureNode.instr)

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
				closureSummary := g.findClosureSummary(boundLabelNode.targetInfo.MakeClosure)
				boundLabelNode.targetAnon = closureSummary // nil is safe
			}
		}
	}
	// Change the built flag to true
	g.built = true
}

// BuildAndRunVisitor runs the pass on the inter-procedural flow graph. First, it calls the BuildGraph function to
// build the inter-procedural dataflow graph. Then, it looks for every entry point designated by the isEntryPoint
// predicate to RunIntraProcedural the visitor on those points (using the [*InterProceduralFlowGraph.RunVisitorOnEntryPoints]
// function).
//
// Most of the logic of the analysis will be in the visitor's implementation by the client. This function is mostly
// a driver that sequences the analyses in the right order with small checks.
//
// This function does nothing if there are no summaries
// (i.e. `len(g.summaries) == 0`)
// or if `cfg.SkipInterprocedural` is set to true.
func (g *InterProceduralFlowGraph) BuildAndRunVisitor(c *AnalyzerState, visitor Visitor,
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
	g.RunVisitorOnEntryPoints(visitor, isEntryPoint, nil)
}

// RunVisitorOnEntryPoints runs the visitor on the entry points designated by either the isEntryPoint function
// or the isGraphEntryPoint function.
func (g *InterProceduralFlowGraph) RunVisitorOnEntryPoints(visitor Visitor,
	isEntryPointSsa func(*config.Config, ssa.Node) bool,
	isEntryPointGraphNode func(node GraphNode) bool) {
	var entryPoints []NodeWithTrace

	for _, summary := range g.Summaries {
		// Identify the entry points for that function: all the call sites that are entry points
		summary.ForAllNodes(func(n GraphNode) {
			if isEntryPointGraphNode != nil && isEntryPointGraphNode(n) {
				for _, callnode := range n.Graph().Callsites {
					contexts := GetAllCallingContexts(g.AnalyzerState, callnode)
					entryPoints = addWithContexts(contexts, n, entryPoints)
				}
			}

			// if the isEntryPointSsa function is not specified, skip the special casing
			if isEntryPointSsa == nil {
				return
			}

			// special cases for each SSA node type supported
			switch node := n.(type) {
			case *SyntheticNode:
				// all synthetic nodes are entry points
				entry := NodeWithTrace{Node: node}
				entryPoints = append(entryPoints, entry)
			case *CallNodeArg:
				if isEntryPointSsa(g.AnalyzerState.Config, node.parent.CallSite().Value()) {
					entry := NodeWithTrace{Node: node, Trace: nil, ClosureTrace: nil}
					entryPoints = append(entryPoints, entry)
				}
			case *CallNode:
				if node.callSite != nil && isEntryPointSsa(g.AnalyzerState.Config, node.callSite.Value()) {
					contexts := GetAllCallingContexts(g.AnalyzerState, node)
					entryPoints = addWithContexts(contexts, node, entryPoints)

					for _, arg := range node.args {
						entryPoints = append(entryPoints, NodeWithTrace{arg, nil, nil})
					}
				}
			}
		})
	}

	g.AnalyzerState.Logger.Debugf("--- # of analysis entrypoints: %d ---\n", len(entryPoints))

	// Run the analysis for every entrypoint. We may be able to change this to RunIntraProcedural the analysis for all entrypoints
	// at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack implements.
	for _, entry := range entryPoints {
		visitor.Visit(g.AnalyzerState, entry)
	}
}

func addWithContexts(contexts []*CallStack, node GraphNode, entryPoints []NodeWithTrace) []NodeWithTrace {
	if contexts == nil {
		// Default is to start without context (trace is nil)
		entry := NodeWithTrace{Node: node, Trace: nil, ClosureTrace: nil}
		entryPoints = append(entryPoints, entry)
	} else {
		for _, ctxt := range contexts {
			entryPoints = append(entryPoints, NodeWithTrace{
				Node:         node,
				Trace:        ctxt,
				ClosureTrace: nil,
			})
		}
	}
	return entryPoints
}

// resolveCalleeSummary fetches the summary of node's callee, using all possible summary resolution methods. It also
// sets the edge from callee to caller, if it could find a summary.
// Returns nil if no summary can be found.
func (g *InterProceduralFlowGraph) resolveCalleeSummary(node *CallNode, nameAliases map[string]*ssa.Function,
	isEntryPoint func(*config.Config, ssa.Node) bool) *SummaryGraph {
	var calleeSummary *SummaryGraph
	logger := g.AnalyzerState.Logger

	// If it's not an interface contract, attempt to just find the summary in the dataflow graph's computed summaries
	if node.callee.Type != InterfaceContract {
		calleeSummary = g.findSummary(node.Callee(), nameAliases)
	}

	if calleeSummary == nil {
		if calleeSummary = NewPredefinedSummary(node.Callee(), GetUniqueFunctionId()); calleeSummary != nil {
			logger.Debugf("Loaded %s from summaries.\n", node.Callee().String())
			g.Summaries[node.Callee()] = calleeSummary

			// If summarization on demand is set and the function is reachable, summarize it if ShouldBuildSummary is true
		} else if g.AnalyzerState.Config.SummarizeOnDemand && ShouldBuildSummary(g.AnalyzerState, node.Callee()) {

			logger.Debugf("Building summary for %v...\n", node.Callee())

			result, err := IntraProceduralAnalysis(
				g.AnalyzerState, node.Callee(), true, GetUniqueFunctionId(), isEntryPoint, nil)

			if err != nil {
				panic(fmt.Errorf("intra-procedural analysis failed for %v: %v", node.Callee(), err))
			}
			logger.Debugf("Finished building summary for %v (%.2f s)", node.Callee(), result.Time.Seconds())

			// Store the computed summary in the graph
			calleeSummary = result.Summary
			g.Summaries[node.Callee()] = calleeSummary
		}
	}

	if calleeSummary != nil && !calleeSummary.Constructed {
		if shortSummary, isPredefined := summaries.SummaryOfFunc(node.Callee()); isPredefined {
			calleeSummary.PopulateGraphFromSummary(shortSummary, false)
			logger.Debugf("Constructed %s from summaries.\n", node.Callee().String())
		}
	}

	// Add edge from callee to caller (adding a call site in the callee)
	if calleeSummary != nil {
		if x := calleeSummary.Callsites[node.CallSite()]; x == nil {
			calleeSummary.Callsites[node.CallSite()] = node
		}
	} else {
		g.summaryNotFound(node)
	}

	return calleeSummary
}

func (g *InterProceduralFlowGraph) findCallPathFromCallNode(origin *CallNode, dest GraphNode) *NodeTree[*CallNode] {
	fmt.Printf("Search for a path from %s to %s\n", origin, dest)
	return nil
}

// findSummary returns the summary graph of f in summaries if present. Returns nil if not.
//
// This will also return a summary if:
//   - f$thunk is the input, and f has a summary, then f's summary is returned
//   - f is the input, and f$thunk has a summary, then f$thunk's summary is returned.
//
// This also holds for f and f$bound. The function checks that the position of the returned summary is the same as the
// position of the function.
func (g *InterProceduralFlowGraph) findSummary(f *ssa.Function, names map[string]*ssa.Function) *SummaryGraph {
	if summary, ok := g.Summaries[f]; ok {
		return summary
	}
	// Check if the function might correspond to a thunk
	actualThunk := g.findSummaryModuloSuffix(f, names, "$thunk")
	if actualThunk != nil {
		return actualThunk
	}
	// Check if the function might correspond to a bound function
	actualBound := g.findSummaryModuloSuffix(f, names, "$bound")
	if actualBound != nil {
		return actualBound
	}

	return nil
}

func (g *InterProceduralFlowGraph) findSummaryModuloSuffix(f *ssa.Function, names map[string]*ssa.Function,
	suffix string) *SummaryGraph {
	// Either the function has been summarized, and we are looking for function + suffix,
	// or the function + suffix has been summarized, and we are looking for the function.
	if alias, ok := names[f.String()+suffix]; ok {
		summary := g.Summaries[alias]
		if summary != nil && f.Pos() == summary.Parent.Pos() {
			return summary
		}
	}
	if alias, ok := names[f.String()]; ok {
		summary := g.Summaries[alias]
		if summary != nil && f.Pos() == summary.Parent.Pos() {
			return summary
		}
	}
	return nil
}

// findClosureSummary returns the summary graph of the function used in the MakeClosure instruction instr
func (g *InterProceduralFlowGraph) findClosureSummary(instr *ssa.MakeClosure) *SummaryGraph {
	switch funcValue := instr.Fn.(type) {
	case *ssa.Function:
		if summary, ok := g.Summaries[funcValue]; ok {
			return summary
		} else {
			return nil
		}
	default:
		return nil
	}
}

func (g *InterProceduralFlowGraph) summaryNotFound(node *CallNode) {
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
// - the CallNode is in the stack
// If no CallNode satisfies these conditions, nil is returned.
func UnwindCallstackFromCallee(callsites map[ssa.CallInstruction]*CallNode, stack *CallStack) *CallNode {
	// no trace = nowhere to return to.
	if stack == nil {
		return nil
	}

	// the number of callsites in a call is expected to be small
	for _, x := range callsites {
		if x.CallSite() == stack.Label.CallSite() && x.Callee() == stack.Label.Callee() {
			return x
		}
	}
	// no return node has been found
	return nil
}

// UnwindCallStackToFunc looks for the callstack pointer where f was called. Returns nil if no such function can be
// found
func UnwindCallStackToFunc(stack *CallStack, f *ssa.Function) *CallStack {
	cur := stack
	for cur != nil {
		if cur.Label.Callee() == f {
			return cur
		}
		cur = cur.Parent
	}
	return nil
}

// CompleteCallStackToNode completes the callstack stack with the call nodes to reach node. Returns nil if node is not
// reachable from the last call node of the stack.
func CompleteCallStackToNode(stack *CallStack, n *CallNode) *CallStack {
	if stack == nil {
		return nil
	}
	if stack.Label == n {
		return stack
	}
	var tmpRoot *CallStack
	tmpRoot = NewNodeTree(stack.Label)
	queue := []*CallStack{tmpRoot}
	for len(queue) > 0 {
		elt := queue[0]
		queue = queue[1:]
		if elt.Label == n {
			return stack.Append(elt)
		}
		for _, callNode := range elt.Label.parent.Callsites {
			queue = append(queue, elt.Add(callNode))
		}
	}
	return stack
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
	summary := NewPredefinedSummary(function, id)
	if summary != nil {
		logger.Debugf("\tLoaded pre-defined summary for %v\n", function)
	} else {
		logger.Debugf("\tBuilding summary for %v...\n", function)
		result, err := IntraProceduralAnalysis(s, function, true, id, isEntrypoint, nil)

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
