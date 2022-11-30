package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"io"
	"log"
)

type IFGraph struct {
	summaries map[*ssa.Function]*SummaryGraph
	callgraph *callgraph.Graph
}

// Print prints each of the function summaries in the graph.
func (ifg IFGraph) Print(w io.Writer) {
	fmt.Fprintf(w, "digraph program {\n")
	for _, summary := range ifg.summaries {
		summary.print(w)
	}
	fmt.Fprintf(w, "}\n")
}

type NodeWithCallStack struct {
	Node  GraphNode
	Stack []*CallNode
}

func (n NodeWithCallStack) StackToString() string {
	s := ""
	for _, node := range n.Stack {
		s = s + "->" + node.String()
	}
	return s
}

// interProceduralPass runs the inter-procedural pass on the inter-procedural flow graph. Candidate taint flows, in the
// form of a map from sink to sources, will be added to taintFlows. Most of the logic is in the visitFromSource
// function that is called for each possible source node identified.
//
// This function does nothing if there are no summaries (i.e. `len(ifg.summaries) == 0` or if `cfg.SkipInterprocedural`
// is set to true.
func (ifg IFGraph) interProceduralPass(cfg *config.Config, logger *log.Logger, taintFlows SinkToSources) {
	// Skip the pass if user configuration demands it
	if cfg.SkipInterprocedural || len(ifg.summaries) == 0 {
		return
	}

	var entryPoints []*SummaryGraph
	// Build the interprocedural graph: link all the summaries together, identify source nodes
	for _, summary := range ifg.summaries {
		if summary == nil {
			continue
		}
		for _, callNodes := range summary.callees {
			for _, node := range callNodes {
				calleeSummary, _ := ifg.summaries[node.callee]
				// If it's not in the generated summaries, try to fetch it from predefined summaries
				if calleeSummary == nil {
					calleeSummary = LoadPredefinedSummary(node.callee, ifg.callgraph)
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

		// Identify the entry points: all the call sites of the sources
		if isSourceFunction(cfg, summary.parent) {
			entryPoints = append(entryPoints, summary)
		}
	}

	logger.Printf("--- # source functions: %d ---\n", len(entryPoints))

	// Run the analysis for every source point. We may be able to change this to run the analysis for all sources
	// at once, but this would require a finer context-tracking mechanism than what the NodeWithCallStack implements.
	for _, entry := range entryPoints {
		for _, node := range entry.callsites {
			visitFromSource(logger, cfg, NodeWithCallStack{Node: node, Stack: []*CallNode{}}, taintFlows)
		}
	}
}

// visitFromSource runs the inter-procedural analysis from a specific source and adds any detected taint flow
// to the taintFlows.
func visitFromSource(logger *log.Logger, cfg *config.Config, source NodeWithCallStack, taintFlows SinkToSources) {
	seen := make(map[GraphNode]bool)
	que := []NodeWithCallStack{source}

	// addNext appends a new node to be visited. First, it will check whether that node has been visited.
	// This operation ensures termination of the algorithm.
	// TODO: consider revisiting nodes in different calling contexts.
	addNext := func(c NodeWithCallStack) {
		if c.Node != nil && !seen[c.Node] {
			que = append(que, c)
			seen[c.Node] = true
		}
	}
	logger.Printf("🍺 ==> Source: %s\n", analysis.Green(source.Node.String()))

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// TODO: optimize call stack
	// TODO: set of visited nodes is not handled properly right now. We should revisit some nodes,
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		elt := que[0] // BFS
		que = que[1:]
		logger.Printf("[%s] Node: %s\n", elt.StackToString(), elt.Node.String())

		// If node is sink, then we reached a sink from a source, and we must log the taint flow.
		if elt.Node.IsSink(cfg) {
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
				addNext(NodeWithCallStack{Node: out, Stack: elt.Stack})
			}

			if len(elt.Stack) >= 1 {
				// This function was called: the value flows back to the call site only
				// TODO: check that this assumption is correct
				callSite := elt.Stack[len(elt.Stack)-1]
				stack := elt.Stack[:len(elt.Stack)-1]
				for x := range callSite.Out() {
					addNext(NodeWithCallStack{Node: x, Stack: stack})
				}
				// Follow taint on matching argument at call site
				arg := callSite.args[graphNode.argPos]
				if arg != nil {
					addNext(NodeWithCallStack{Node: arg, Stack: stack})
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.parent.callsites {
					callSiteArg := callSite.args[graphNode.argPos]
					for x := range callSiteArg.Out() {
						addNext(NodeWithCallStack{Node: x, Stack: []*CallNode{}})
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
			stack := append(elt.Stack, callSite)

			if callSite.calleeSummary == nil { // this function has not been summarized
				logger.Printf(analysis.Red(fmt.Sprintf("%s has not been summarized.", callSite.String())))
				if callSite.callee != nil {
					logger.Printf(fmt.Sprintf("Please add %s to summaries", callSite.callee.String()))
				}
				break
			}
			if !callSite.calleeSummary.constructed {
				logger.Printf("%s: summary has not been built for %s.",
					analysis.Yellow("WARNING"),
					analysis.Yellow(elt.Node.Graph().parent.Name()))
			}

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.calleeSummary.parent.Params[graphNode.argPos]
			if param != nil {
				x := callSite.calleeSummary.params[param]
				addNext(NodeWithCallStack{Node: x, Stack: stack})
			}

			// Handle the flows inside the function: the outgoing edges computed for the summary
			for out := range graphNode.Out() {
				addNext(NodeWithCallStack{Node: out, Stack: elt.Stack})
			}

		// This is a return node. We have reached this from any node in the return node's function.
		// The data will flow to the caller.
		// If the stack is non-empty, then the data flows to back the call site in the stack(the CallNode).
		// If the stack is empty, then the data flows back to every possible call site according to the call
		// graph.
		case *ReturnNode:
			if len(elt.Stack) >= 1 {
				// This function was called: the value flows back to the call site only
				// TODO: check that this assumption is correct
				caller := elt.Stack[len(elt.Stack)-1]
				stack := elt.Stack[:len(elt.Stack)-1]
				for x := range caller.Out() {
					addNext(NodeWithCallStack{Node: x, Stack: stack})
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.parent.callsites {
					for x := range callSite.Out() {
						addNext(NodeWithCallStack{Node: x, Stack: []*CallNode{}})
					}
				}
			}

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *CallNode:
			// We pop the call from the stack and continue inside the caller
			var stack []*CallNode
			if len(elt.Stack) > 0 {
				stack = elt.Stack[:len(elt.Stack)-1]
			}
			for x := range graphNode.Out() {
				addNext(NodeWithCallStack{Node: x, Stack: stack})
			}
		}
	}
}

// addNewPathCandidate adds a new path between a source and a sink to paths using the information in elt
// returns true if it adds a new path.
// @requires elt.Node.IsSink()
func addNewPathCandidate(paths SinkToSources, source GraphNode, sink GraphNode) bool {
	var sourceInstr ssa.CallInstruction
	var sinkInstr ssa.CallInstruction

	// The sink is the current node. Since elt.Node.IsSink() should be true,
	switch node := source.(type) {
	case *CallNode:
		sourceInstr = node.callSite
	case *CallNodeArg:
		sourceInstr = node.parent.callSite
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
