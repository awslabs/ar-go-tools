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
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// Visitor represents a visitor that runs an inter-procedural analysis from entrypoint.
type Visitor interface {
	Visit(s *State, entrypoint NodeWithTrace)
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
	AnalyzerState *State

	// built indicates whether this graph has been built
	// this should only be set to true by BuildGraph() and be false by default
	built bool

	// Globals are edges between global nodes and the nodes that access the global
	Globals map[*GlobalNode]map[*AccessGlobalNode]bool
}

// NewInterProceduralFlowGraph returns a new non-built cross function flow graph.
func NewInterProceduralFlowGraph(summaries map[*ssa.Function]*SummaryGraph,
	state *State) InterProceduralFlowGraph {

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
func (g *InterProceduralFlowGraph) BuildGraph() {
	c := g.AnalyzerState
	logger := c.Logger

	logger.Debugf("Building inter-procedural flow graph...")

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
					externalContractSummary := g.AnalyzerState.LoadExternalContractSummary(node)
					if externalContractSummary != nil {
						logger.Debugf("Loaded %s from external contracts.\n",
							formatutil.SanitizeRepr(node.Callee()))

						// Perform soundness check on the external summary
						isSound, reason, needsDeeperCheck := g.CheckSummarySoundness(node.Callee(), externalContractSummary)
						if !isSound {
							logger.Warnf("External summary for %s is not sound: %s",
								formatutil.SanitizeRepr(node.Callee()), reason)
							// Continue with the summary, but mark it as potentially problematic
							// In the future, we might want to create a new summary or take other actions
						} else {
							logger.Debugf("External summary for %s is sound: %s",
								formatutil.SanitizeRepr(node.Callee()), reason)

							// If we need to dive deeper into callees, log this information
							if len(needsDeeperCheck) > 0 {
								logger.Debugf("Summary for %s requires deeper analysis of %d callees",
									formatutil.SanitizeRepr(node.Callee()), len(needsDeeperCheck))
								// Here we might want to recursively check these callees
								// For now, we just log the information
							}
						}

						// Use the summary regardless of soundness check result
						// In the future, we might decide to reject unsound summaries
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

	// Writes the summaries to file if the option is set
	if summariesFile != nil {
		// Read-only operation on summaries
		go func() {
			for _, summary := range g.Summaries {
				if summary == nil {
					continue
				}
				_, _ = summariesFile.WriteString(fmt.Sprintf("%s:\n", summary.Parent.String()))
				summary.Print(false, summariesFile)
				_, _ = summariesFile.WriteString("\n")
			}
		}()
	}

	// STEP 3: link all the summaries together
	for _, summary := range g.Summaries {
		if summary == nil {
			continue
		}
		// Interprocedural edges: callers to callees
		for _, callNodes := range summary.Callees {
			for _, node := range callNodes {
				if node.Callee() != nil && node.CalleeSummary == nil &&
					g.AnalyzerState.IsReachableFunction(node.Callee()) {
					node.CalleeSummary = g.resolveCalleeSummary(node, nameAliases)
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
		for _, boundLabelNodeGroup := range summary.BoundLabelNodes {
			for _, boundLabelNode := range boundLabelNodeGroup {
				if boundLabelNode.targetInfo.MakeClosure != nil {
					closureSummary := g.findClosureSummary(boundLabelNode.targetInfo.MakeClosure)
					boundLabelNode.targetAnon = closureSummary // nil is safe
				}
			}
		}
	}
	// Change the built flag to true
	g.built = true
}

// Sync synchronizes inter-procedural information in the graph. This is useful if updating a summary generates nodes
// that may require edges to nodes in other functions.
//
//gocyclo:ignore
func (g *InterProceduralFlowGraph) Sync() {
	if !g.built {
		g.AnalyzerState.Logger.Warnf("Attempting to sync an inter-procedural graph that has not been built.")
	}
	for _, summary := range g.Summaries {
		if summary == nil {
			continue
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
		for _, boundLabelNodeGroup := range summary.BoundLabelNodes {
			for _, boundLabelNode := range boundLabelNodeGroup {
				if boundLabelNode.targetInfo.MakeClosure != nil {
					closureSummary := g.findClosureSummary(boundLabelNode.targetInfo.MakeClosure)
					boundLabelNode.targetAnon = closureSummary // nil is safe
				}
			}
		}
	}
}

// ScanningSpec specifies what nodes should be scanned. The caller can use both the ssa node and the graph node
// predicates to identify graph nodes that are the entry points of the analysis.
type ScanningSpec struct {
	// IsEntryPointSsa identifies graph nodes by the ssa node they represent.
	// It returns the code identifier from the config file if there was a match.
	IsEntryPointSsa func(node ssa.Node) (config.CodeIdentifier, bool)

	// IsEntryPointGraph identifies graph nodes directly as entry points.
	// It returns the code identifier from the config file if there was a match.
	IsEntryPointGraph func(node GraphNode) (config.CodeIdentifier, bool)

	// MarkCallArgsLikeCall specifies whether call arguments should be considered entry points when the call is
	// an entry point.
	MarkCallArgsLikeCall bool

	// ScanCallArgsOnly specifies whether only call arguments should be
	// considered entry points - not the call itself.
	ScanCallArgsOnly bool
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
func (g *InterProceduralFlowGraph) BuildAndRunVisitor(c *State, visitor Visitor, spec ScanningSpec) {
	// Skip the pass if user configuration demands it
	if !c.Config.SummarizeOnDemand && len(g.Summaries) == 0 {
		c.Logger.Infof("Skipping inter-procedural pass: no summaries, and not summarizing on demand.")
		return
	}

	// Build the inter-procedural flow graph
	g.BuildGraph()

	// Open the coverage file if specified in configuration
	coverage := openCoverage(c)
	if coverage != nil {
		defer coverage.Close()
	}

	// Run the analysis
	g.RunVisitorOnEntryPoints(visitor, spec)
}

// RunVisitorOnEntryPoints runs the visitor on the entry points designated by either the isEntryPoint function
// or the isGraphEntryPoint function.
func (g *InterProceduralFlowGraph) RunVisitorOnEntryPoints(visitor Visitor, spec ScanningSpec) {

	g.AnalyzerState.Logger.Infof("Scanning for entry points ...\n")
	entryPoints := make(map[KeyType]NodeWithTrace)
	for _, summary := range g.Summaries {
		// Identify the entry points for that function: all the call sites that are entry points
		summary.ForAllNodes(scanEntryPoints(g, spec, entryPoints))
	}

	g.AnalyzerState.Logger.Infoboxf(" %d analysis entry points", len(entryPoints))
	if g.AnalyzerState.Logger.LogsDebug() {
		for _, entryPoint := range entryPoints {
			g.AnalyzerState.Logger.Debugf("Entry: %s", entryPoint.Node)
			g.AnalyzerState.Logger.Debugf("      in context %s", entryPoint.Trace)
		}
	}

	// Run the analysis for every entrypoint. We may be able to change this to RunIntraProcedural the analysis for all
	// entrypoints at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack
	// implements.
	// If the maximum number of alarms has been reached, stop early.
	i := 0
	for _, entry := range entryPoints {
		if !g.AnalyzerState.TestAlarmCount() {
			g.AnalyzerState.Logger.Warnf("%d entrypoints are skipped, max number of alarms reached.",
				len(entryPoints)-i)
			return
		}

		// Run visitor with timeout protection
		g.runVisitorWithTimeout(visitor, entry, i+1, len(entryPoints))
		i++
	}
}

// runVisitorWithTimeout runs the visitor on an entry point with timeout protection
func (g *InterProceduralFlowGraph) runVisitorWithTimeout(visitor Visitor, entry NodeWithTrace, current, total int) {
	timeout := 10 * time.Second // Use 10 seconds for inter-procedural entry points
	done := make(chan bool, 1)
	cancelled := make(chan bool, 1)

	// Run visitor in separate goroutine
	go func() {
		visitor.Visit(g.AnalyzerState, entry)
		done <- true
	}()

	// Start timeout monitoring goroutine
	go func() {
		time.Sleep(timeout)
		cancelled <- true
	}()

	// Race between completion and cancellation
	select {
	case <-done:
		// Visitor completed within timeout
		return
	case <-cancelled:
		// Timeout occurred - log and continue
		g.AnalyzerState.Logger.Warnf("Entry point %d/%d (%s) cancelled due to time out",
			current, total, entry.Node.String())
		return
	}
}

// TODO this will likely get refactored in the future anyways
//
//gocyclo:ignore
func scanEntryPoints(
	g *InterProceduralFlowGraph,
	spec ScanningSpec,
	entryPoints map[KeyType]NodeWithTrace) func(n GraphNode) {
	return func(n GraphNode) {
		if spec.IsEntryPointGraph != nil {
			if _, ok := spec.IsEntryPointGraph(n); ok {
				switch node := n.(type) {
				case *CallNodeArg:
					contexts := GetAllCallingContexts(g.AnalyzerState, node.ParentNode())
					nodes := addContexts(contexts, node)
					for _, nt := range nodes {
						entryPoints[nt.Key()] = nt
					}
					return
				}

				for _, callnode := range n.Graph().Callsites {
					contexts := GetAllCallingContexts(g.AnalyzerState, callnode)
					nodes := addContexts(contexts, n)
					for _, node := range nodes {
						entryPoints[node.Key()] = node
					}
				}
			}
		}
		// if the isEntryPointSsa function is not specified, skip the special casing
		if spec.IsEntryPointSsa == nil {
			return
		}

		// special cases for each SSA node type supported
		// TODO: try to factor out the special cases in the isEntryPointGraphNode functions
		switch node := n.(type) {
		case *SyntheticNode:
			addSyntheticNodeEntryPoints(spec, entryPoints, node)
		case *CallNodeArg:
			if spec.MarkCallArgsLikeCall {
				if _, ok := spec.IsEntryPointSsa(node.parent.CallSite().Value()); ok {
					entry := NodeWithTrace{Node: node, Trace: nil, ClosureTrace: nil}
					entryPoints[entry.Key()] = entry
				}
			}
		case *CallNode:
			if node.callSite == nil {
				return
			}

			if cid, ok := spec.IsEntryPointSsa(node.callSite.Value()); ok {
				if funcutil.Exists(cid.Target.Objects, func(obj config.TargetObject) bool {
					return obj.Kind == config.ArgumentKind
				}) {
					// Matching cid has an argument object which means the call itself is not an entrypoint
					return
				}

				contexts := GetAllCallingContexts(g.AnalyzerState, node)
				nodes := addContexts(contexts, node)
				for _, node := range nodes {
					entryPoints[node.Key()] = node
				}

				if spec.MarkCallArgsLikeCall {
					for _, arg := range node.args {
						entry := NodeWithTrace{arg, nil, nil}
						entryPoints[entry.Key()] = entry
					}
				}
			}
		}
	}
}

func addSyntheticNodeEntryPoints(
	spec ScanningSpec,
	entryPoints map[KeyType]NodeWithTrace,
	node *SyntheticNode) {
	if spec.IsEntryPointSsa == nil {
		return
	}
	asValue, isValue := node.Instr().(ssa.Node)
	if !isValue {
		return
	}
	if _, ok := spec.IsEntryPointSsa(asValue); ok {
		entry := NodeWithTrace{Node: node}
		entryPoints[entry.Key()] = entry
	}
}

// addContexts returns a new NodeWithTrace for each calling context of node.
// If contexts is empty or nil, then the node is returned without context.
func addContexts(contexts []*CallStack, node GraphNode) []NodeWithTrace {
	var res []NodeWithTrace
	if len(contexts) == 0 {
		// Default behaviour is to start without context (trace is nil)
		node := NodeWithTrace{Node: node, Trace: nil, ClosureTrace: nil}
		res = append(res, node)
	} else {
		for _, ctxt := range contexts {
			n := NodeWithTrace{
				Node:         node,
				Trace:        ctxt,
				ClosureTrace: nil,
			}
			res = append(res, n)
		}
	}

	return res
}

// resolveCalleeSummary fetches the summary of node's callee, using all possible summary resolution methods. It also
// sets the edge from callee to caller, if it could find a summary.
// Returns nil if no summary can be found.
func (g *InterProceduralFlowGraph) resolveCalleeSummary(node *CallNode,
	nameAliases map[string]*ssa.Function) *SummaryGraph {
	var calleeSummary *SummaryGraph
	logger := g.AnalyzerState.Logger

	// If it's not an interface contract, attempt to just find the summary in the dataflow graph's computed summaries
	if node.callee.Type != lang.InterfaceContract {
		calleeSummary = g.findSummary(node.Callee(), nameAliases)
	}

	if calleeSummary == nil {
		calleeSummary, err := NewPredefinedSummary(node.Callee(), GetUniqueFunctionID())
		if err != nil {
			// An error in our own predefined summaries: this should not happen, but panic if we missed something.
			panic(fmt.Errorf("could not create summary for %s: %s", formatutil.SanitizeRepr(node.Callee()), err))
		}
		if calleeSummary != nil {
			logger.Debugf("Loaded %s from summaries.\n", formatutil.SanitizeRepr(node.Callee()))
			g.Summaries[node.Callee()] = calleeSummary
		}
	}

	if calleeSummary != nil && !calleeSummary.Constructed {
		if shortSummary, isPredefined := summaries.SummaryOfFunc(node.Callee()); isPredefined {
			calleeSummary.PopulateGraphFromSummary(shortSummary, false)
			// Mark predefined summaries as sound
			calleeSummary.IsSound = true
			logger.Debugf("Constructed %s from summaries.\n", formatutil.SanitizeRepr(node.Callee()))
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
		}
		return nil

	default:
		return nil
	}
}

func (g *InterProceduralFlowGraph) summaryNotFound(node *CallNode) {
	if node.callee.Callee.Name() != "init" &&
		g.AnalyzerState.IsReachableFunction(node.callee.Callee) {

		g.AnalyzerState.Logger.Debugf("Could not find summary of %s", node.callSite)
		if node.callee.Callee != nil {
			g.AnalyzerState.Logger.Debugf("|-- Key: %s", formatutil.SanitizeRepr(node.callee.Callee))
		}
		g.AnalyzerState.Logger.Debugf("|-- Location: %s", node.Position(g.AnalyzerState))

		if node.callSite.Common().IsInvoke() {
			g.AnalyzerState.Logger.Debugf("|-- invoke resolved to callee %s",
				formatutil.SanitizeRepr(node.callee.Callee))
		}
	}
}

// openCoverage opens the coverage file, if the config requires it.
// the caller is responsible for closing the file if non-nil
func openCoverage(c *State) *os.File {
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
func openSummaries(c *State) *os.File {
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

// debugSummaryFlows outputs detailed flow information for the three summaries used in soundness checking
func (g *InterProceduralFlowGraph) debugSummaryFlows(function *ssa.Function, Su, Sg, Sp *SummaryGraph) {
	g.AnalyzerState.Logger.Debugf("=== SUMMARY FLOWS DEBUG for %s ===", function.Name())

	// Debug Su (Summary Under Check)
	// g.AnalyzerState.Logger.Debugf("--- Su (Summary Under Check) ---")
	// g.logSummaryFlows(Su)

	// // Debug Sg (Most General)
	// g.AnalyzerState.Logger.Debugf("--- Sg (Most General) ---")
	// g.logSummaryFlows(Sg)

	// // Debug Sp (Most Preserved)
	// g.AnalyzerState.Logger.Debugf("--- Sp (Most Preserved) ---")
	// g.logSummaryFlows(Sp)

	// Show comparison results
	g.AnalyzerState.Logger.Debugf("--- Comparison Results ---")
	g.AnalyzerState.Logger.Debugf("Sp == Sg: %v", g.compareSummaries(Sp, Sg))
	g.AnalyzerState.Logger.Debugf("Sp ⊆ Su: %v", g.isSummarySubset(Sp, Su))
	g.AnalyzerState.Logger.Debugf("Su ⊆ Sg: %v", g.isSummarySubset(Su, Sg))
	g.AnalyzerState.Logger.Debugf("Su == Sg: %v", g.compareSummaries(Su, Sg))
	g.AnalyzerState.Logger.Debugf("Sp == Su: %v", g.compareSummaries(Sp, Su))

	g.AnalyzerState.Logger.Debugf("=== END SUMMARY FLOWS DEBUG ===")
}

// // logSummaryFlows logs detailed flow information for a single summary
// func (g *InterProceduralFlowGraph) logSummaryFlows(summary *SummaryGraph) {
// 	if summary == nil {
// 		g.AnalyzerState.Logger.Debugf("  Summary: nil")
// 		return
// 	}

// 	// Count nodes and edges
// 	nodeCount := 0
// 	edgeCount := 0
// 	nodeTypes := make(map[string]int)

// 	summary.ForAllNodes(func(node GraphNode) {
// 		nodeCount++
// 		nodeType := g.getNodeTypeName(node)
// 		nodeTypes[nodeType]++
// 		edgeCount += len(node.Out())
// 	})

// 	g.AnalyzerState.Logger.Debugf("  Total Nodes: %d, Total Edges: %d", nodeCount, edgeCount)
// 	g.AnalyzerState.Logger.Debugf("  Node Types: %v", nodeTypes)

// 	// Show detailed node and edge information
// 	g.AnalyzerState.Logger.Debugf("  Detailed Flows:")
// 	summary.ForAllNodes(func(node GraphNode) {
// 		if len(node.Out()) > 0 {
// 			g.AnalyzerState.Logger.Debugf("    %s:", node.String())
// 			for dest, edgeInfos := range node.Out() {
// 				for _, edgeInfo := range edgeInfos {
// 					condStr := "unconditional"
// 					if edgeInfo.Cond != nil && !edgeInfo.Cond.Satisfiable {
// 						condStr = "never"
// 					} else if edgeInfo.Cond != nil && len(edgeInfo.Cond.Conditions) > 0 {
// 						condStr = fmt.Sprintf("conditional(%d)", len(edgeInfo.Cond.Conditions))
// 					}
// 					pathStr := ""
// 					if len(edgeInfo.RelPath) > 0 {
// 						pathStr = fmt.Sprintf(" [paths: %d]", len(edgeInfo.RelPath))
// 					}
// 					g.AnalyzerState.Logger.Debugf("      → %s (%s)%s", dest.String(), condStr, pathStr)
// 				}
// 			}
// 		}
// 	})
// }

// // getNodeTypeName returns a simplified type name for logging
// func (g *InterProceduralFlowGraph) getNodeTypeName(node GraphNode) string {
// 	switch node.(type) {
// 	case *ParamNode:
// 		return "Param"
// 	case *CallNode:
// 		return "Call"
// 	case *CallNodeArg:
// 		return "CallArg"
// 	case *ReturnValNode:
// 		return "Return"
// 	case *SyntheticNode:
// 		return "Synthetic"
// 	case *BuiltinCallNode:
// 		return "Builtin"
// 	case *ClosureNode:
// 		return "Closure"
// 	case *BoundVarNode:
// 		return "BoundVar"
// 	case *AccessGlobalNode:
// 		return "Global"
// 	case *FreeVarNode:
// 		return "FreeVar"
// 	case *IfNode:
// 		return "If"
// 	case *BoundLabelNode:
// 		return "BoundLabel"
// 	default:
// 		return fmt.Sprintf("%T", node)
// 	}
// }

// CheckSummarySoundness checks if a summary is sound by comparing three types of summaries:
// - Most-general (Sg): assumes every callee function has maximum possible dataflows.
// - Most-preserved (Sp): assumes no dataflows between callees - only analyzing dataflow within the function body itself.
// - Summary-under-check (Su): the provided summary we're evaluating.
//
// It returns true if the summary is sound, false otherwise. It also returns a string explaining the reason
// for the decision, and a map of callee functions that need deeper analysis (if applicable).
func (g *InterProceduralFlowGraph) CheckSummarySoundness(
	function *ssa.Function,
	summaryUnderCheck *SummaryGraph) (bool, string, map[*ssa.Function]*SummaryGraph) {

	// Clone the summary-under-check to avoid modifying the original
	Su := summaryUnderCheck
	// Create a most-general summary (Sg) where every callee function has maximum dataflows
	Sg := g.createMostGeneralSummary(function)

	// Create a most-preserved summary (Sp) with no dataflows between callees
	Sp := g.createMostPreservedSummary(function)

	// Debug: Output detailed flow information if debug logging is enabled
	if g.AnalyzerState.Logger.LogsDebug() {
		g.debugSummaryFlows(function, Su, Sg, Sp)
	}

	// Compare summaries to determine the case
	spEqualsSg := g.compareSummaries(Sp, Sg)
	spSubsetOfSu := g.isSummarySubset(Sp, Su)
	suSubsetOfSg := g.isSummarySubset(Su, Sg)
	suEqualsSg := g.compareSummaries(Su, Sg)
	spEqualsSu := g.compareSummaries(Sp, Su)

	// Initialize map for callees that need deeper analysis
	calleesDiveDeeperMap := make(map[*ssa.Function]*SummaryGraph)

	if spEqualsSg {
		// Case 1: Sp = Sg
		// In this case they should be just the targeted dataflow facts
		// We don't need to recursively go down for any callee
		Su.IsSound = true
		return true, "Summary is sound: Sp = Sg, these are the targeted dataflow facts", nil
	} else if spSubsetOfSu && suSubsetOfSg && !suEqualsSg {
		// Case 2: Sp ⊆ Su ⊂ Sg
		// We need to check evidence by diving deeper into callees
		for _, calleeNodes := range Su.Callees {
			for _, callNode := range calleeNodes {
				if callNode.Callee() != nil {
					// For each callee Gi, we need to check (Su∖Sp)∩Gi
					// Add this callee to the map of functions to analyze deeper
					calleesDiveDeeperMap[callNode.Callee()] = g.createIntersectionSummary(Su, Sp, callNode.Callee())
				}
			}
		}
		Su.IsSound = true
		return true, "Summary is sound but needs evidence check: Sp ⊆ Su ⊂ Sg", calleesDiveDeeperMap
	} else if !spEqualsSu && suEqualsSg {
		// Case 3: Sp ⊂ Su = Sg
		// Just take Su, no need to check callees
		Su.IsSound = true
		return true, "Summary is sound: Sp ⊂ Su = Sg, taking Su", nil
	} else {
		// Case 4: Otherwise, it's unsound
		Su.IsSound = false
		return false, "Summary is unsound: need to iterate again or perform non-LLM analysis", nil
	}
}

// createMostGeneralSummary creates a summary where every callee function has maximum possible dataflows.
// This represents Sg (most-general summary) in the summary soundness check.
//
//gocyclo:ignore
func (g *InterProceduralFlowGraph) createMostGeneralSummary(function *ssa.Function) *SummaryGraph {
	// Validate input parameters
	if g == nil {
		panic("InterProceduralFlowGraph is nil")
	}
	if g.AnalyzerState == nil {
		panic("AnalyzerState is nil")
	}
	if function == nil {
		panic("function parameter is nil")
	}

	// Get or create a fresh summary for the function
	summary := g.Summaries[function]
	if summary == nil {
		id := GetUniqueFunctionID()
		summary = NewSummaryGraph(g.AnalyzerState, function, id, IsNodeOfInterest, nil)
		if summary == nil {
			panic(fmt.Sprintf("failed to create summary for function %v", function))
		}
		// Clone the summary to avoid modifying the original
		// summary = g.cloneSummary(summary)
	} else {
		// Clone the summary to avoid modifying the original
		summary = g.cloneSummary(summary)
		if summary == nil {
			panic(fmt.Sprintf("failed to clone summary for function %v", function))
		}
	}

	// Validate summary state after creation/cloning
	if summary.Parent == nil {
		panic(fmt.Sprintf("summary.Parent is nil for function %v", function))
	}

	// Check if function has valid implementation
	if len(function.Blocks) == 0 {
		g.AnalyzerState.Logger.Debugf("Function %v has no blocks, skipping intra-procedural analysis", function)
		// For functions with no blocks, create a minimal summary
		summary.Constructed = true
		summary.IsSound = true
		return summary
	}

	if len(function.Blocks[0].Instrs) == 0 {
		g.AnalyzerState.Logger.Debugf("Function %v has no instructions in first block, skipping intra-procedural analysis", function)
		// For functions with no instructions, create a minimal summary
		summary.Constructed = true
		summary.IsSound = true
		return summary
	}

	// For each callee, create full dataflow connections
	for _, calleeMap := range summary.Callees {
		for _, callNode := range calleeMap {
			// For most-general, assume every callee has full dataflow
			if callNode != nil && callNode.Callee() != nil {
				// If the callee doesn't have a summary, create one
				if callNode.CalleeSummary == nil {
					id := GetUniqueFunctionID()
					calleeSummary := NewSummaryGraph(g.AnalyzerState, callNode.Callee(), id, IsNodeOfInterest, nil)
					if calleeSummary != nil {
						callNode.CalleeSummary = calleeSummary
						g.Summaries[callNode.Callee()] = calleeSummary
						// For most-general, always build a full flow graph
						callNode.CalleeSummary.BuildFullFlowGraph()
					}
				} else if !callNode.CalleeSummary.IsSound {
					// If the callee's summary is not sound, build a full flow graph
					callNode.CalleeSummary.BuildFullFlowGraph()
				}
				// If the summary is sound, respect it and don't modify it
			}
		}
	}

	// Validate summary state before running intra-procedural analysis
	if summary.shouldTrack == nil {
		g.AnalyzerState.Logger.Debugf("Setting shouldTrack to IsNodeOfInterest for function %v", function)
		summary.shouldTrack = IsNodeOfInterest
	}

	// Additional validation before RunIntraProcedural
	if summary.Parent != function {
		panic(fmt.Sprintf("summary.Parent (%v) doesn't match function parameter (%v)", summary.Parent, function))
	}

	// Perform intra-procedural analysis on our carefully crafted summary
	_, err := RunIntraProcedural(g.AnalyzerState, summary)
	if err != nil {
		// Log error but continue with the summary we've built so far
		g.AnalyzerState.Logger.Warnf("Failed to analyze function %v with maximum callee flows: %v", function, err)
		summary.BuildFullFlowGraph() // Fallback to full connectivity
		// Mark as constructed even if analysis failed
		summary.Constructed = true
		summary.IsSound = false // Mark as unsound due to analysis failure
		return summary
	}

	// Mark the summary as constructed and sound
	summary.Constructed = true
	summary.IsSound = true
	summary.SyncGlobals()

	// Use the analyzed summary as our most-general summary
	return summary
}

// createMostPreservedSummary creates a summary assuming no dataflows between callees.
// This represents Sp (most-preserved summary) in the summary soundness check.
func (g *InterProceduralFlowGraph) createMostPreservedSummary(function *ssa.Function) *SummaryGraph {
	// Get or create a fresh summary for the function
	summary := g.Summaries[function]
	if summary == nil {
		id := GetUniqueFunctionID()
		summary = NewSummaryGraph(g.AnalyzerState, function, id, IsNodeOfInterest, nil)
		// Clone the summary to avoid modifying the original
		// summary = g.cloneSummary(summary)
	} else {
		// Clone the summary to avoid modifying the original
		summary = g.cloneSummary(summary)
	}

	// For each callee, create empty summaries with no dataflows
	for _, calleeMap := range summary.Callees {
		for _, callNode := range calleeMap {
			// For most-preserved, assume every callee has no internal dataflows
			if callNode.Callee() != nil {
				// If the callee doesn't have a summary, create one
				if callNode.CalleeSummary == nil {
					id := GetUniqueFunctionID()
					calleeSummary := NewSummaryGraph(g.AnalyzerState, callNode.Callee(), id, IsNodeOfInterest, nil)
					callNode.CalleeSummary = calleeSummary
					g.Summaries[callNode.Callee()] = calleeSummary
					// In theory the summary is already empty, here we just call the BuildEmptyGraph to actually enforce it
					callNode.CalleeSummary.BuildEmptyGraph()
				} else if !callNode.CalleeSummary.IsSound {
					// If it has a summary, create a fresh empty clone of it
					emptyCalleeSummary := g.cloneSummary(callNode.CalleeSummary)
					// Use BuildEmptyGraph to clear all edges from the callee summary to represent no dataflows
					emptyCalleeSummary.BuildEmptyGraph()
					callNode.CalleeSummary = emptyCalleeSummary
				}
			}
		}
	}

	// Validate summary state before running intra-procedural analysis
	if summary.shouldTrack == nil {
		g.AnalyzerState.Logger.Debugf("Setting shouldTrack to IsNodeOfInterest for function %v", function)
		summary.shouldTrack = IsNodeOfInterest
	}
	// Perform intra-procedural analysis on our carefully crafted summary
	_, err := RunIntraProcedural(g.AnalyzerState, summary)
	if err != nil {
		// Log error but continue with the summary we've built so far
		g.AnalyzerState.Logger.Warnf("Failed to analyze function %v with minimal callee flows: %v", function, err)
		summary.BuildEmptyGraph() // Fallback to no connectivity
		return summary
	}

	// Mark the summary as constructed and sound
	summary.Constructed = true
	summary.IsSound = true
	summary.SyncGlobals()

	// Use the analyzed summary as our most-preserved summary
	return summary
}

// extractParamFlows extracts parameter-to-parameter and parameter-to-return flows from a summary,
// using transitive closure to find all reachable parameters and returns, ignoring self-loops.
func (g *InterProceduralFlowGraph) extractParamFlows(summary *SummaryGraph) map[string]bool {
	flows := make(map[string]bool)

	if summary == nil {
		return flows
	}

	// Collect all target nodes (parameters and return values) into a set for efficient lookup
	targetNodes := make(map[GraphNode]bool)
	for _, paramNode := range summary.Params {
		targetNodes[paramNode] = true
	}
	for _, retNodes := range summary.Returns {
		for _, ret := range retNodes {
			if ret != nil { // Return nodes can be nil for constant values
				targetNodes[ret] = true
			}
		}
	}

	// For each parameter, find all reachable target nodes using DFS
	for _, paramNode := range summary.Params {
		visited := make(map[GraphNode]bool)
		reachableTargets := g.findReachableTargets(paramNode, targetNodes, visited)

		// Record flows to reachable target nodes (excluding self-loops)
		for _, target := range reachableTargets {
			if target != paramNode { // Skip self-loops
				flowKey := fmt.Sprintf("%s -> %s", paramNode.String(), target.String())
				flows[flowKey] = true
			}
		}
	}

	return flows
}

// findReachableTargets performs DFS traversal to find all reachable target nodes
// from the given start node, avoiding cycles using the visited set.
// targetNodes specifies which nodes we consider as valid targets (params and returns).
func (g *InterProceduralFlowGraph) findReachableTargets(startNode GraphNode, targetNodes map[GraphNode]bool, visited map[GraphNode]bool) []GraphNode {
	var targets []GraphNode

	// Mark current node as visited to prevent cycles
	visited[startNode] = true

	// If the current node is a target node, add it to results
	if targetNodes[startNode] {
		targets = append(targets, startNode)
	}

	// Explore all outgoing edges
	for destNode := range startNode.Out() {
		// Skip already visited nodes to prevent cycles
		if visited[destNode] {
			continue
		}

		// Recursively explore this destination node
		subTargets := g.findReachableTargets(destNode, targetNodes, visited)
		targets = append(targets, subTargets...)
	}

	return targets
}

// compareSummaries compares two summaries and returns true if they are equivalent.
// Only compares parameter-to-parameter and parameter-to-return relationships, ignoring self-loops.
func (g *InterProceduralFlowGraph) compareSummaries(summary1, summary2 *SummaryGraph) bool {
	if summary1 == nil || summary2 == nil {
		return summary1 == summary2
	}

	// Extract relevant flows from both summaries
	flows1 := g.extractParamFlows(summary1)
	flows2 := g.extractParamFlows(summary2)

	// Compare the flow sets
	if len(flows1) != len(flows2) {
		return false
	}

	for flow1 := range flows1 {
		if _, exists := flows2[flow1]; !exists {
			return false
		}
	}

	return true
}

// isSummarySubset checks if summary1 is a subset of summary2 (summary1 ⊆ summary2).
// Only considers parameter-to-parameter and parameter-to-return relationships, ignoring self-loops.
func (g *InterProceduralFlowGraph) isSummarySubset(summary1, summary2 *SummaryGraph) bool {
	if summary1 == nil {
		return true // Empty set is a subset of any set
	}
	if summary2 == nil {
		return false // Non-empty set cannot be a subset of an empty set
	}

	// Extract relevant flows from both summaries
	flows1 := g.extractParamFlows(summary1)
	flows2 := g.extractParamFlows(summary2)

	// Check if all flows in summary1 exist in summary2
	for flow1 := range flows1 {
		if _, exists := flows2[flow1]; !exists {
			return false
		}
	}

	return true
}

// compareEdgeInfo compares two EdgeInfo structures and returns true if they are equivalent.
func (g *InterProceduralFlowGraph) compareEdgeInfo(ei1, ei2 EdgeInfo) bool {
	// Check if indices match
	if ei1.Index != ei2.Index {
		return false
	}

	// Compare conditions (either both nil or both equal)
	if (ei1.Cond == nil) != (ei2.Cond == nil) {
		return false
	}
	if ei1.Cond != nil && ei2.Cond != nil {
		if ei1.Cond.Satisfiable != ei2.Cond.Satisfiable {
			return false
		}
		if len(ei1.Cond.Conditions) != len(ei2.Cond.Conditions) {
			return false
		}
		// For simplicity, we're not comparing the actual condition contents
	}

	// Compare RelPath maps
	if len(ei1.RelPath) != len(ei2.RelPath) {
		return false
	}

	// Check if all paths in ei1 exist in ei2
	for inPath1, outPaths1 := range ei1.RelPath {
		outPaths2, exists := ei2.RelPath[inPath1]
		if !exists {
			return false
		}

		if len(outPaths1) != len(outPaths2) {
			return false
		}

		for outPath1 := range outPaths1 {
			if _, exists := outPaths2[outPath1]; !exists {
				return false
			}
		}
	}

	return true
}

// createEmptySummaryClone creates a new SummaryGraph with the same metadata as the original.
func (g *InterProceduralFlowGraph) createEmptySummaryClone(original *SummaryGraph) *SummaryGraph {
	return &SummaryGraph{
		ID:                    original.ID,
		Constructed:           original.Constructed,
		IsInterfaceContract:   original.IsInterfaceContract,
		IsPreSummarized:       original.IsPreSummarized,
		IsSound:               original.IsSound, // Copy the sound flag to preserve it during cloning
		Parent:                original.Parent,
		Params:                make(map[ssa.Node]*ParamNode),
		FreeVars:              make(map[ssa.Node]*FreeVarNode),
		Callees:               make(map[ssa.CallInstruction]map[*ssa.Function]*CallNode),
		Callsites:             make(map[ssa.CallInstruction]*CallNode),
		BuiltinCalls:          make(map[ssa.CallInstruction]*BuiltinCallNode),
		Returns:               make(map[ssa.Instruction][]*ReturnValNode),
		CreatedClosures:       make(map[ssa.Instruction]*ClosureNode),
		ReferringMakeClosures: make(map[ssa.Instruction]*ClosureNode),
		AccessGlobalNodes:     make(map[ssa.Instruction]map[ssa.Value]*AccessGlobalNode),
		SyntheticNodes:        make(map[ssa.Instruction]*SyntheticNode),
		BoundLabelNodes:       make(map[ssa.Instruction]map[BindingInfo]*BoundLabelNode),
		Ifs:                   make(map[ssa.Instruction]*IfNode),
		errors:                make(map[error]bool),
		lastNodeID:            original.lastNodeID,
		shouldTrack:           original.shouldTrack,
		postBlockCallBack:     original.postBlockCallBack,
	}
}

// cloneParameterNodes clones all parameter nodes from the original graph to the clone.
func (g *InterProceduralFlowGraph) cloneParameterNodes(
	original *SummaryGraph,
	clone *SummaryGraph,
	nodeMapping map[GraphNode]GraphNode) {

	// Clone parameters
	for k, v := range original.Params {
		paramNode := &ParamNode{
			id:      v.id,
			parent:  clone,
			ssaNode: v.ssaNode,
			out:     make(map[GraphNode][]EdgeInfo),
			in:      make(map[GraphNode]EdgeInfo),
			argPos:  v.argPos,
		}
		clone.Params[k] = paramNode
		nodeMapping[v] = paramNode
	}

	// Clone free variables
	for k, v := range original.FreeVars {
		freeVarNode := &FreeVarNode{
			id:      v.id,
			parent:  clone,
			ssaNode: v.ssaNode,
			out:     make(map[GraphNode][]EdgeInfo),
			in:      make(map[GraphNode]EdgeInfo),
			fvPos:   v.fvPos,
		}
		clone.FreeVars[k] = freeVarNode
		nodeMapping[v] = freeVarNode
	}
}

// cloneCalleeNodes clones all callee and call nodes from the original graph to the clone.
func (g *InterProceduralFlowGraph) cloneCalleeNodes(
	original *SummaryGraph,
	clone *SummaryGraph,
	nodeMapping map[GraphNode]GraphNode) {

	// Clone callees and call nodes
	for instr, calleeMap := range original.Callees {
		clone.Callees[instr] = make(map[*ssa.Function]*CallNode)
		for fn, callNode := range calleeMap {
			newCallNode := &CallNode{
				id:            callNode.id,
				parent:        clone,
				callee:        callNode.callee,
				CalleeSummary: callNode.CalleeSummary, // Reference to the original callee summary
				args:          make([]*CallNodeArg, len(callNode.args)),
				callSite:      callNode.callSite,
				out:           make(map[GraphNode][]EdgeInfo),
				in:            make(map[GraphNode]EdgeInfo),
			}

			// Clone args
			for i, arg := range callNode.args {
				callNodeArg := &CallNodeArg{
					id:        arg.id,
					parent:    newCallNode,
					ssaValue:  arg.ssaValue,
					argPos:    arg.argPos,
					out:       make(map[GraphNode][]EdgeInfo),
					in:        make(map[GraphNode]EdgeInfo),
					paramName: arg.paramName,
				}
				newCallNode.args[i] = callNodeArg
				nodeMapping[arg] = callNodeArg
			}

			clone.Callees[instr][fn] = newCallNode
			clone.Callsites[instr] = newCallNode
			nodeMapping[callNode] = newCallNode
		}
	}
}

// cloneBuiltinCallNodes clones all builtin call nodes from the original graph to the clone.
func (g *InterProceduralFlowGraph) cloneBuiltinCallNodes(
	original *SummaryGraph,
	clone *SummaryGraph,
	nodeMapping map[GraphNode]GraphNode) {

	// Clone builtin calls
	for instr, builtinCall := range original.BuiltinCalls {
		builtinCallNode := &BuiltinCallNode{
			id:       builtinCall.id,
			parent:   clone,
			callSite: builtinCall.callSite,
			name:     builtinCall.name,
			out:      make(map[GraphNode][]EdgeInfo),
			in:       make(map[GraphNode]EdgeInfo),
			marks:    builtinCall.marks, // This might need deeper cloning if mutable
		}
		clone.BuiltinCalls[instr] = builtinCallNode
		nodeMapping[builtinCall] = builtinCallNode
	}
}

// cloneReturnNodes clones all return value nodes from the original graph to the clone.
func (g *InterProceduralFlowGraph) cloneReturnNodes(
	original *SummaryGraph,
	clone *SummaryGraph,
	nodeMapping map[GraphNode]GraphNode) {

	// Clone return values
	for instr, returnValNodes := range original.Returns {
		clonedReturnNodes := make([]*ReturnValNode, len(returnValNodes))
		for i, returnNode := range returnValNodes {
			if returnNode != nil {
				// ReturnValNode now has both 'in' and 'out' fields
				returnValNode := &ReturnValNode{
					id:     returnNode.id,
					parent: clone,
					index:  returnNode.index,
					in:     make(map[GraphNode]EdgeInfo),
					out:    make(map[GraphNode][]EdgeInfo),
				}
				clonedReturnNodes[i] = returnValNode
				nodeMapping[returnNode] = returnValNode
			}
		}
		clone.Returns[instr] = clonedReturnNodes
	}
}

// cloneClosureNodes clones all closure nodes from the original graph to the clone.
func (g *InterProceduralFlowGraph) cloneClosureNodes(
	original *SummaryGraph,
	clone *SummaryGraph,
	nodeMapping map[GraphNode]GraphNode) {

	// Clone closure nodes
	for instr, closureNode := range original.CreatedClosures {
		clonedClosureNode := &ClosureNode{
			id:             closureNode.id,
			parent:         clone,
			ClosureSummary: closureNode.ClosureSummary, // Reference to the original closure summary
			instr:          closureNode.instr,
			boundVars:      make([]*BoundVarNode, len(closureNode.boundVars)),
			out:            make(map[GraphNode][]EdgeInfo),
			in:             make(map[GraphNode]EdgeInfo),
		}

		// Clone bound variables
		for i, boundVar := range closureNode.boundVars {
			boundVarNode := &BoundVarNode{
				id:       boundVar.id,
				parent:   clonedClosureNode,
				ssaValue: boundVar.ssaValue,
				bPos:     boundVar.bPos,
				out:      make(map[GraphNode][]EdgeInfo),
				in:       make(map[GraphNode]EdgeInfo),
			}
			clonedClosureNode.boundVars[i] = boundVarNode
			nodeMapping[boundVar] = boundVarNode
		}

		clone.CreatedClosures[instr] = clonedClosureNode
		nodeMapping[closureNode] = clonedClosureNode
	}

	// Clone referring make closures
	for instr, makeClosure := range original.ReferringMakeClosures {
		// These should be references to closure nodes we've already created
		if clonedNode, exists := nodeMapping[makeClosure]; exists {
			clone.ReferringMakeClosures[instr] = clonedNode.(*ClosureNode)
		}
	}
}

// cloneMiscNodes clones various other node types (synthetic, bound label, if, access global)
// from the original graph to the clone.
func (g *InterProceduralFlowGraph) cloneMiscNodes(
	original *SummaryGraph,
	clone *SummaryGraph,
	nodeMapping map[GraphNode]GraphNode) {

	// Clone synthetic nodes
	for instr, syntheticNode := range original.SyntheticNodes {
		synNode := &SyntheticNode{
			id:     syntheticNode.id,
			parent: clone,
			instr:  syntheticNode.instr,
			label:  syntheticNode.label,
			out:    make(map[GraphNode][]EdgeInfo),
			in:     make(map[GraphNode]EdgeInfo),
		}
		clone.SyntheticNodes[instr] = synNode
		nodeMapping[syntheticNode] = synNode
	}

	// Clone bound label nodes
	for instr, boundLabelMap := range original.BoundLabelNodes {
		clone.BoundLabelNodes[instr] = make(map[BindingInfo]*BoundLabelNode)
		for bindingInfo, boundLabelNode := range boundLabelMap {
			blNode := &BoundLabelNode{
				id:         boundLabelNode.id,
				parent:     clone,
				instr:      boundLabelNode.instr,
				label:      boundLabelNode.label, // Might need deep copy if label is mutable
				targetInfo: boundLabelNode.targetInfo,
				targetAnon: boundLabelNode.targetAnon, // Reference to the original target
				out:        make(map[GraphNode][]EdgeInfo),
				in:         make(map[GraphNode]EdgeInfo),
			}
			clone.BoundLabelNodes[instr][bindingInfo] = blNode
			nodeMapping[boundLabelNode] = blNode
		}
	}

	// Clone if nodes
	for instr, ifNode := range original.Ifs {
		ifn := &IfNode{
			id:      ifNode.id,
			parent:  clone,
			ssaNode: ifNode.ssaNode,
			out:     make(map[GraphNode][]EdgeInfo),
			in:      make(map[GraphNode]EdgeInfo),
		}
		clone.Ifs[instr] = ifn
		nodeMapping[ifNode] = ifn
	}

	// Clone access global nodes
	for instr, globalMap := range original.AccessGlobalNodes {
		clone.AccessGlobalNodes[instr] = make(map[ssa.Value]*AccessGlobalNode)
		for value, accessGlobalNode := range globalMap {
			agNode := &AccessGlobalNode{
				id:      accessGlobalNode.id,
				IsWrite: accessGlobalNode.IsWrite,
				graph:   clone,
				instr:   accessGlobalNode.instr,
				Global:  accessGlobalNode.Global, // Reference to the original global
				out:     make(map[GraphNode][]EdgeInfo),
				in:      make(map[GraphNode]EdgeInfo),
			}
			clone.AccessGlobalNodes[instr][value] = agNode
			nodeMapping[accessGlobalNode] = agNode
		}
	}

	// Clone errors
	for err := range original.errors {
		clone.errors[err] = true
	}
}

// cloneEdgeInfo creates a deep copy of an EdgeInfo structure.
func (g *InterProceduralFlowGraph) cloneEdgeInfo(ei EdgeInfo) EdgeInfo {
	clonedEdgeInfo := EdgeInfo{
		Index: ei.Index,
		Cond:  ei.Cond, // Might need deep copy if condition is mutable
	}

	// Clone RelPath map
	clonedRelPath := make(map[string]map[string]bool)
	for inPath, outPathMap := range ei.RelPath {
		clonedOutPathMap := make(map[string]bool)
		for outPath, val := range outPathMap {
			clonedOutPathMap[outPath] = val
		}
		clonedRelPath[inPath] = clonedOutPathMap
	}
	clonedEdgeInfo.RelPath = clonedRelPath

	return clonedEdgeInfo
}

// restoreEdges recreates all the edges between nodes in the cloned graph.
func (g *InterProceduralFlowGraph) restoreEdges(
	original *SummaryGraph,
	nodeMapping map[GraphNode]GraphNode) {

	original.ForAllNodes(func(origNode GraphNode) {
		// Get the corresponding cloned node
		clonedNode, exists := nodeMapping[origNode]
		if !exists {
			return
		}

		// Copy outgoing edges
		for destOrigNode, edgeInfos := range origNode.Out() {
			destClonedNode, destExists := nodeMapping[destOrigNode]
			if !destExists {
				continue
			}

			// Clone edge infos
			clonedEdgeInfos := make([]EdgeInfo, len(edgeInfos))
			for i, ei := range edgeInfos {
				clonedEdgeInfos[i] = g.cloneEdgeInfo(ei)
			}

			// Add edge to cloned node
			outMap := clonedNode.Out()
			outMap[destClonedNode] = clonedEdgeInfos

			// Add corresponding in-edge
			// We use the first edge info as representative for the in-edge
			if len(clonedEdgeInfos) > 0 {
				addInEdge(destClonedNode, clonedNode, clonedEdgeInfos[0])
			}
		}
	})
}

// cloneSummary creates a complete deep copy of a SummaryGraph to avoid modifying the original.
// This function delegates to helper functions to keep its complexity manageable.
func (g *InterProceduralFlowGraph) cloneSummary(original *SummaryGraph) *SummaryGraph {
	if original == nil {
		return nil
	}

	// Create the base summary structure
	clone := g.createEmptySummaryClone(original)

	// Create a node mapping to help restore edges later
	nodeMapping := make(map[GraphNode]GraphNode)

	// Clone all the different types of nodes
	g.cloneParameterNodes(original, clone, nodeMapping)
	g.cloneCalleeNodes(original, clone, nodeMapping)
	g.cloneBuiltinCallNodes(original, clone, nodeMapping)
	g.cloneReturnNodes(original, clone, nodeMapping)
	g.cloneClosureNodes(original, clone, nodeMapping)
	g.cloneMiscNodes(original, clone, nodeMapping)

	// Restore all the edges between nodes
	g.restoreEdges(original, nodeMapping)

	return clone
}

// isNodeRelatedToCallee checks if a node is related to a specific callee function.
func (g *InterProceduralFlowGraph) isNodeRelatedToCallee(node GraphNode, callee *ssa.Function) bool {
	switch n := node.(type) {
	case *CallNode:
		return n.Callee() == callee
	case *CallNodeArg:
		return n.ParentNode().Callee() == callee
	default:
		return false
	}
}

// findCorrespondingNode finds a node in the target graph that corresponds to the source node.
func (g *InterProceduralFlowGraph) findCorrespondingNode(sourceNode GraphNode, targetGraph *SummaryGraph) (GraphNode, bool) {
	var result GraphNode
	found := false

	targetGraph.ForAllNodes(func(node GraphNode) {
		if node.String() == sourceNode.String() {
			result = node
			found = true
		}
	})

	return result, found
}

// findEdgeDifferences identifies edges that exist in sourceNode but not in targetNode.
// It returns a list of edges (destination nodes and edge infos) that should be added to the result graph.
func (g *InterProceduralFlowGraph) findEdgeDifferences(
	sourceNode, targetNode GraphNode,
	sourceGraph, targetGraph *SummaryGraph) map[GraphNode][]EdgeInfo {

	differences := make(map[GraphNode][]EdgeInfo)

	// For each outgoing edge from the source node
	for destSourceNode, edgeInfos1 := range sourceNode.Out() {
		// Find corresponding destination node in target graph
		destTargetNode, destFound := g.findCorrespondingNode(destSourceNode, targetGraph)

		if !destFound {
			// The edge exists in source but not in target
			differences[destSourceNode] = edgeInfos1
			continue
		}

		// Check if the edge infos are different
		targetEdgeInfos := targetNode.Out()[destTargetNode]

		// For each EdgeInfo in the source, check if it exists in the target
		for _, ei1 := range edgeInfos1 {
			edgeExists := false

			for _, ei2 := range targetEdgeInfos {
				if g.compareEdgeInfo(ei1, ei2) {
					edgeExists = true
					break
				}
			}

			if !edgeExists {
				// This specific edge info doesn't exist in the target
				if _, ok := differences[destSourceNode]; !ok {
					differences[destSourceNode] = []EdgeInfo{ei1}
				} else {
					differences[destSourceNode] = append(differences[destSourceNode], ei1)
				}
			}
		}
	}

	return differences
}

// createIntersectionSummary creates a summary representing (Su∖Sp)∩Gi for a given callee.
// This computes the difference between Su and Sp, then intersects it with the callee's summary.
func (g *InterProceduralFlowGraph) createIntersectionSummary(Su, Sp *SummaryGraph, callee *ssa.Function) *SummaryGraph {
	// Get or create the callee's summary
	calleeSummary := g.Summaries[callee]
	if calleeSummary == nil {
		id := GetUniqueFunctionID()
		calleeSummary = NewSummaryGraph(g.AnalyzerState, callee, id, nil, nil)
	}

	// Clone the callee summary to avoid modifying the original
	result := g.cloneSummary(calleeSummary)

	// Process each node in Su that is related to this callee
	Su.ForAllNodes(func(suNode GraphNode) {
		// Skip nodes not related to the callee
		if !g.isNodeRelatedToCallee(suNode, callee) {
			return
		}

		// Find corresponding node in Sp
		spNode, nodeInSp := g.findCorrespondingNode(suNode, Sp)

		// If the node doesn't exist in Sp, it's fully in Su∖Sp
		// (In a complete implementation, we would add this node and all its edges)
		if !nodeInSp {
			return
		}

		// Find edges that exist in Su but not in Sp
		edgeDifferences := g.findEdgeDifferences(suNode, spNode, Su, Sp)

		// In a complete implementation, we would add these edge differences to the result summary
		// For now, we're just identifying the differences but not actually modifying the result
		if len(edgeDifferences) > 0 {
			g.AnalyzerState.Logger.Debugf(
				"Found %d edge differences for node %s in function %s",
				len(edgeDifferences), suNode.String(), callee.String())
		}
	})

	return result
}

// PerformDataflowAnalysis performs intra-procedural dataflow analysis on the given function,
// assuming all callees have already been summarized.
// It returns a summary graph representing which variables can flow to which other variables.
func (g *InterProceduralFlowGraph) PerformDataflowAnalysis(function *ssa.Function) (*SummaryGraph, error) {
	if function == nil {
		return nil, fmt.Errorf("cannot analyze nil function")
	}

	// Check if we already have a summary for this function
	if summary, ok := g.Summaries[function]; ok && summary.Constructed {
		return summary, nil
	}

	// Get or create a new summary
	//TODO: It should be guaranteed to be sound, cnosidering add a field to summary to mark it's sound or not
	// Panic if it's unsound here
	var summary *SummaryGraph
	if existingSummary, ok := g.Summaries[function]; ok {
		summary = existingSummary
	} else {
		id := GetUniqueFunctionID()
		summary = NewSummaryGraph(g.AnalyzerState, function, id, nil, nil)
		g.Summaries[function] = summary
	}

	// Perform the intra-procedural analysis
	elapsed, err := RunIntraProcedural(g.AnalyzerState, summary)
	if err != nil {
		return nil, fmt.Errorf("dataflow analysis failed for %v: %w", function, err)
	}

	g.AnalyzerState.Logger.Debugf("PerformDataflowAnalysis: Finished analyzing %v (%.2f s)",
		function, elapsed.Seconds())

	// Mark the summary as constructed and sound (since it's computed by the program)
	summary.Constructed = true
	summary.IsSound = true

	// Synchronize global information
	summary.SyncGlobals()

	return summary, nil
}

// BuildSummary builds a summary for function and returns it.
// If the summary was already built, i.e. there in a summary corresponding to the function in the flow graph, then
// the summary is constructed by running the intra-procedural dataflow analysis.
// If the summary was not already in the flow graph of the state, it creates a new summary, adds it to the flow graph
// and then runs the intra-procedural dataflow analysis.
//
// BuildSummary expects to be called only on reachable functions, because the analyses usually instantiate the summaries
// only for those functions.
func BuildSummary(s *State, function *ssa.Function) *SummaryGraph {
	summary := s.FlowGraph.Summaries[function]
	if summary != nil && summary.Constructed {
		return summary
	}
	// nil summaries should only happen for functions that should have an internally defined summary, i.e. standard library.
	if summary == nil {
		id := GetUniqueFunctionID()
		predef, err := NewPredefinedSummary(function, id)
		if err != nil {
			// An error in the predefined summaries: this should not happen
			panic(fmt.Errorf("could not create summary for %v: %v", function, err))
		}
		if predef != nil {
			s.FlowGraph.Summaries[function] = predef
			summary = predef
		}
	}
	// Summary is still nil, we should panic now.
	if summary == nil {
		panic(fmt.Errorf("summary for function %v is nil", function))
	}

	logger := s.Logger

	logger.Debugf("BuildSummary: Constructing summary for %v...\n", function)
	elapsed, err := RunIntraProcedural(s, summary)

	if err != nil {
		panic(fmt.Errorf("single function analysis failed for %v: %v", function, err))
	}

	logger.Debugf("BuildSummary: Finished constructing summary for %v (%.2f s)", function, elapsed.Seconds())

	// Mark the summary as sound since it was computed by the program
	summary.IsSound = true

	return summary
}
