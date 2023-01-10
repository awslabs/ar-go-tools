package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/ssa"
	"io"
	"log"
	"os"
	"strings"
)

type IFGraph struct {
	summaries map[*ssa.Function]*SummaryGraph
	cache     *analysis.Cache
}

// Print prints each of the function summaries in the graph.
func (ifg IFGraph) Print(w io.Writer) {
	fmt.Fprintf(w, "digraph program {\n")
	for _, summary := range ifg.summaries {
		summary.print(w)
	}
	fmt.Fprintf(w, "}\n")
}

// Trace is a doubly-linked list with a pointer to origin where each node is a call site
type Trace struct {
	Call   *CallNode
	Origin *Trace
	Parent *Trace
	Next   []*Trace
	len    int
}

func NewTrace(initNode *CallNode) *Trace {
	origin := &Trace{Call: initNode, Parent: nil, Next: []*Trace{}, len: 1}
	origin.Origin = origin
	return origin
}

func (n *Trace) String() string {
	if n == nil || n.len == 0 {
		return ""
	}
	s := make([]string, n.len)
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.len >= 1 {
			s[cur.len-1] = cur.Call.FuncName()
		}
	}
	return strings.Join(s, "_")
}

// IsLasso checks returns true if the trace is more than one node long and the current node
func (n *Trace) IsLasso() bool {
	if n == nil || n.len <= 1 {
		return false
	}
	last := n
	for cur := last.Parent; cur != nil; cur = cur.Parent {
		if cur.Call.FuncName() == last.Call.FuncName() {
			return true
		}
	}
	return false
}

func (n *Trace) Add(callNode *CallNode) *Trace {
	if n == nil {
		return NewTrace(callNode)
	} else {
		newNode := &Trace{Call: callNode, Parent: n, Next: []*Trace{}, Origin: n.Origin, len: n.len + 1}
		n.Next = append(n.Next, newNode)
		return newNode
	}

}

type NodeWithTrace struct {
	Node  GraphNode
	Trace *Trace
}

// crossFunctionPass runs the inter-procedural pass on the inter-procedural flow graph. Candidate taint flows, in the
// form of a map from sink to sources, will be added to taintFlows. Most of the logic is in the visitFromSource
// function that is called for each possible source node identified.
//
// This function does nothing if there are no summaries (i.e. `len(ifg.summaries) == 0` or if `cfg.SkipInterprocedural`
// is set to true.
func (ifg IFGraph) crossFunctionPass(cfg *config.Config, logger *log.Logger, taintFlows SinkToSources) {
	var err error
	var sourceFuncs []*SummaryGraph
	var entryPoints []NodeWithTrace

	// Skip the pass if user configuration demands it
	if cfg.SkipInterprocedural || len(ifg.summaries) == 0 {
		return
	}
	// Open the coverage file if specified in configuration
	var coverage *os.File
	if cfg.CoverageFile != "" {
		coverage, err = os.Create(cfg.CoverageFile)
		defer coverage.Close()
		if err != nil {
			coverage = nil
			logger.Printf("Warning: could not create coverage file %s, continuing.\n", cfg.CoverageFile)
			logger.Printf("Error was: %s", err)
		} else {
			_, _ = coverage.WriteString("mode: set\n")
		}
	}

	// Open a file to output summaries
	var summariesFile *os.File
	if cfg.OutputSummaries {
		summariesFile, err = os.Create("flow-summaries.out")
		defer summariesFile.Close()
		if err != nil {
			coverage = nil
			logger.Printf("Warning: could not create summaries files, continuing.\n")
			logger.Printf("Error was: %s", err)
		}
	}

	// Build the interprocedural graph: link all the summaries together, identify source nodes
	for _, summary := range ifg.summaries {
		if summary == nil {
			continue
		}
		if summariesFile != nil {
			_, _ = summariesFile.WriteString(fmt.Sprintf("%s:\n", summary.parent.String()))
			summary.print(summariesFile)
			_, _ = summariesFile.WriteString("\n")
		}
		for _, callNodes := range summary.callees {
			for _, node := range callNodes {
				if node.callee != nil {
					calleeSummary := findCalleeSummary(node.callee, ifg.summaries)
					// If it's not in the generated summaries, try to fetch it from predefined summaries
					if calleeSummary == nil {
						calleeSummary = LoadPredefinedSummary(node.callee, ifg.cache.PointerAnalysis.CallGraph)
						if calleeSummary != nil {
							logger.Printf("Loaded %s from summaries.\n", node.callee.String())
							ifg.summaries[node.callee] = calleeSummary
						}
					}
					// Add edge from callee to caller (adding a call site in the callee)
					if calleeSummary != nil {
						calleeSummary.callsites[node.callSite] = node
					}
					node.calleeSummary = calleeSummary // nil is safe
				}
			}
		}

		// Identify the entry points for that function: all the call sites if it is a source, and all the synthetic
		// nodes that are sources in the function body.
		for _, snode := range summary.syntheticNodes {
			entry := NodeWithTrace{Node: snode, Trace: nil}
			entryPoints = append(entryPoints, entry)
		}
		if isSourceFunction(cfg, summary.parent) {
			sourceFuncs = append(sourceFuncs, summary)
		}
	}

	for _, summary := range sourceFuncs {
		for _, node := range summary.callsites {
			entry := NodeWithTrace{node, nil}
			entryPoints = append(entryPoints, entry)
		}
	}

	logger.Printf("--- # sources of tainted data: %d ---\n", len(entryPoints))

	// Run the analysis for every source point. We may be able to change this to run the analysis for all sources
	// at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack implements.
	for _, entry := range entryPoints {
		visitFromSource(logger, ifg.cache, entry, taintFlows, coverage)
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
		if (strings.HasPrefix(callee.Name(), summarized.Name()) || strings.HasPrefix(summarized.Name(), callee.Name())) &&
			callee.Pos() == summarized.Pos() {
			return summary
		}
	}

	return nil
}

// visitFromSource runs the inter-procedural analysis from a specific source and adds any detected taint flow
// to the taintFlows.
func visitFromSource(logger *log.Logger, c *analysis.Cache, source NodeWithTrace, taintFlows SinkToSources,
	coverage *os.File) {
	seen := make(map[NodeWithTrace]bool)
	que := []NodeWithTrace{source}

	// addNext appends a new node to be visited. First, it will check whether that node has been visited.
	// This operation ensures termination of the algorithm.
	// TODO: consider revisiting nodes in different calling contexts.
	addNext := func(c NodeWithTrace) {
		if c.Node != nil && !seen[c] && !c.Trace.IsLasso() {
			que = append(que, c)
			seen[c] = true
		}
	}
	logger.Printf("🍺 ==> Source: %s\n", analysis.Green(source.Node.String()))
	logger.Printf("%s %s\n", analysis.Green("Found at"), source.Node.Position())

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// TODO: optimize call stack
	// TODO: set of visited nodes is not handled properly right now. We should revisit some nodes,
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		elt := que[len(que)-1]
		que = que[:len(que)-1]
		pos := elt.Node.Position()
		if coverage != nil && pos.String() != "unknown" && pos.String() != "-" {
			if strings.Contains(pos.Filename, c.Config.Coverage) {
				_, _ = coverage.WriteString(
					fmt.Sprintf("%s:%d.1,%d.%d 1 1\n",
						pos.Filename, pos.Line, pos.Line, pos.Column))
			}
		}

		// If node is sink, then we reached a sink from a source, and we must log the taint flow.
		if elt.Node.IsSink(c.Config) {
			if addNewPathCandidate(taintFlows, source.Node, elt.Node) {
				logger.Printf(" 💀 Add new path from %s to %s <== \n",
					analysis.Green(source.Node.String()), analysis.Red(elt.Node.String()))
			}
			// A sink does not have successors in the taint flow analysis (but other sinks can be reached
			// as there are still values flowing).
			continue
		}

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().constructed {
			logger.Printf("%s: summary has not been built for %s.",
				analysis.Yellow("WARNING"),
				analysis.Yellow(elt.Node.Graph().parent.Name()))
			continue
		}

		switch graphNode := elt.Node.(type) {

		// This is a parameter node. We have reached this node either from a function call and the stack is non-empty,
		// or we reached this node from another flow inside the function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		//- if the stack is empty, there is no calling context. The flow goes back to every possible call site of
		// the function's parameter.
		case *ParamNode:
			// Flows inside the function
			for out := range graphNode.Out() {
				addNext(NodeWithTrace{Node: out, Trace: elt.Trace})
			}

			if elt.Trace != nil {
				// This function was called: the value flows back to the call site only
				// TODO: check that this assumption is correct
				callSite := elt.Trace.Call
				if graphNode.argPos >= len(callSite.args) {
					logger.Fatalf("Argument number mismatch: trying to access argument %d of %s, which has"+
						" only %d arguments\nSee: %s\n", graphNode.argPos, callSite.String(), len(callSite.args),
						analysis.SafeValuePos(callSite.callSite.Value()))
				}
				// Follow taint on matching argument at call site
				arg := callSite.args[graphNode.argPos]
				if arg != nil {
					addNext(NodeWithTrace{Node: arg, Trace: elt.Trace.Parent})
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.parent.callsites {
					callSiteArg := callSite.args[graphNode.argPos]
					for x := range callSiteArg.Out() {
						addNext(NodeWithTrace{Node: x, Trace: nil})
					}
				}
			}

		// This is a call site argument. We have reached this either returning from a call, from the callee's parameter
		// node, or we reached this inside a function from another node.
		// In either case, the flow continues inside the function to the graphNode.Out() children and to the callee's
		// parameters
		case *CallNodeArg:
			// Flow to next call
			callSite := graphNode.parent

			if callSite.calleeSummary == nil { // this function has not been summarized
				var typeString string
				if callSite.callee == nil {
					typeString = "nil callee"
				} else {
					typeString = callSite.callee.Type().String()
				}
				logger.Printf(analysis.Red(fmt.Sprintf("| %s has not been summarized (call %s).",
					callSite.String(), typeString)))
				if callSite.callee != nil && callSite.callSite != nil {
					logger.Printf(fmt.Sprintf("| Please add %s to summaries", callSite.callee.String()))
					logger.Printf(fmt.Sprintf("|_ See call site: %s", callSite.Position()))
				}
				break
			}
			if !callSite.calleeSummary.constructed {
				logger.Printf("| %s: summary has not been built for %s.",
					analysis.Yellow("WARNING"),
					analysis.Yellow(elt.Node.Graph().parent.Name()))
				logger.Printf(fmt.Sprintf("|_ See call site: %s", callSite.Position()))
			}

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.calleeSummary.parent.Params[graphNode.argPos]
			if param != nil {
				x := callSite.calleeSummary.params[param]
				addNext(NodeWithTrace{Node: x, Trace: elt.Trace.Add(callSite)})
			}

			// Handle the flows inside the function: the outgoing edges computed for the summary
			for out := range graphNode.Out() {
				addNext(NodeWithTrace{Node: out, Trace: elt.Trace})
			}

		// This is a return node. We have reached this from any node in the return node's function.
		// The data will flow to the caller.
		// If the stack is non-empty, then the data flows to back the call site in the stack(the CallNode).
		// If the stack is empty, then the data flows back to every possible call site according to the call
		// graph.
		case *ReturnNode:
			if elt.Trace != nil {
				// This function was called: the value flows back to the call site only
				// TODO: check that this assumption is correct
				caller := elt.Trace.Call
				for x := range caller.Out() {
					addNext(NodeWithTrace{Node: x, Trace: elt.Trace.Parent})
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.parent.callsites {
					for x := range callSite.Out() {
						addNext(NodeWithTrace{Node: x, Trace: nil})
					}
				}
			}

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *CallNode:
			// We pop the call from the stack and continue inside the caller
			var trace *Trace
			if elt.Trace != nil {
				trace = elt.Trace.Parent
			}
			for x := range graphNode.Out() {
				addNext(NodeWithTrace{Node: x, Trace: trace})
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only need to follow the
		// outgoing edges
		case *SyntheticNode:
			for x := range graphNode.Out() {
				addNext(NodeWithTrace{Node: x, Trace: elt.Trace})
			}
		}
	}
}

// addNewPathCandidate adds a new path between a source and a sink to paths using the information in elt
// returns true if it adds a new path.
// @requires elt.Node.IsSink()
func addNewPathCandidate(paths SinkToSources, source GraphNode, sink GraphNode) bool {
	var sourceInstr ssa.Instruction
	var sinkInstr ssa.CallInstruction

	// The sink is the current node. Since elt.Node.IsSink() should be true,
	switch node := source.(type) {
	case *CallNode:
		sourceInstr = node.callSite
	case *CallNodeArg:
		sourceInstr = node.parent.callSite
	case *SyntheticNode:
		sourceInstr = node.instr
	}

	switch node := sink.(type) {
	case *CallNode:
		sinkInstr = node.callSite
	case *CallNodeArg:
		sinkInstr = node.parent.callSite
	}

	if sinkInstr != nil && sourceInstr != nil {
		if _, ok := paths[sinkInstr.(ssa.Instruction)]; !ok {
			paths[sinkInstr.(ssa.Instruction)] = make(map[ssa.Instruction]bool)
		}
		paths[sinkInstr.(ssa.Instruction)][sourceInstr] = true
		return true
	}
	return false
}
