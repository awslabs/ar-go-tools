package taint

import (
	"fmt"
	"io"
	"log"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/format"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/packagescan"
	"golang.org/x/tools/go/ssa"
)

// visitFromSource runs the inter-procedural analysis from a specific source and adds any detected taint flow
// to the taintFlows.
func visitFromSource(logger *log.Logger, c *dataflow.Cache, source dataflow.NodeWithTrace, taintFlows dataflow.DataFlows,
	coverage io.StringWriter) {
	seen := make(map[dataflow.NodeWithTrace]bool)
	que := []dataflow.NodeWithTrace{source}

	// addNext appends a new node to be visited. First, it will check whether that node has been visited.
	// This operation ensures termination of the algorithm.
	// TODO: consider revisiting nodes in different calling contexts.
	addNext := func(c dataflow.NodeWithTrace) {
		if c.Node != nil && !seen[c] && !c.Trace.IsLasso() {
			que = append(que, c)
			seen[c] = true
		}
	}
	logger.Printf("🍺 ==> Source: %s\n", format.Green(source.Node.String()))
	logger.Printf("%s %s\n", format.Green("Found at"), source.Node.Position())

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
		if isSink(elt.Node, c.Config) {
			if addNewPathCandidate(taintFlows, source.Node, elt.Node) {
				logger.Printf(" 💀 Add new path from %s to %s <== \n",
					format.Green(source.Node.String()), format.Red(elt.Node.String()))
			}
			// A sink does not have successors in the taint flow analysis (but other sinks can be reached
			// as there are still values flowing).
			continue
		}

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().Constructed {
			logger.Printf("%s: summary has not been built for %s.",
				format.Yellow("WARNING"),
				format.Yellow(elt.Node.Graph().Parent.Name()))
			continue
		}

		switch graphNode := elt.Node.(type) {

		// This is a parameter node. We have reached this node either from a function call and the stack is non-empty,
		// or we reached this node from another flow inside the function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		//- if the stack is empty, there is no calling context. The flow goes back to every possible call site of
		// the function's parameter.
		case *dataflow.ParamNode:
			// Flows inside the function body. The data propagates to other locations inside the function body
			for out := range graphNode.Out() {
				addNext(dataflow.NodeWithTrace{Node: out, Trace: elt.Trace})
			}

			// Then we take care of the flows that go back to the callsite of the current function.
			// for example:
			// func f(s string, s2 *string) { *s2 = s }
			// The data can propagate from s to s2: we visit s from a callsite f(tainted, next), then
			// visit the parameter s2, and then next needs to be visited by going back to the callsite.
			if elt.Trace != nil {
				// This function was called: the value flows back to the call site only
				// TODO: check that this assumption is correct
				callSite := elt.Trace.Call
				if graphNode.Index() >= len(callSite.Args()) {
					logger.Fatalf("Argument number mismatch: trying to access argument %d of %s, which has"+
						" only %d arguments\nSee: %s\n", graphNode.Index(), callSite.String(), len(callSite.Args()),
						packagescan.SafeValuePos(callSite.CallSite().Value()))
				}
				// Follow taint on matching argument at call site
				arg := callSite.Args()[graphNode.Index()]
				if arg != nil {
					addNext(dataflow.NodeWithTrace{Node: arg, Trace: elt.Trace.Parent})
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					callSiteArg := callSite.Args()[graphNode.Index()]
					for x := range callSiteArg.Out() {
						addNext(dataflow.NodeWithTrace{Node: x, Trace: nil})
					}
				}
			}

		// This is a call site argument. We have reached this either returning from a call, from the callee's parameter
		// node, or we reached this inside a function from another node.
		// In either case, the flow continues inside the function to the graphNode.Out() children and to the callee's
		// parameters
		case *dataflow.CallNodeArg:
			// Flow to next call
			callSite := graphNode.ParentNode()

			if callSite.CalleeSummary == nil { // this function has not been summarized
				var typeString string
				if callSite.Callee() == nil {
					typeString = "nil callee"
				} else {
					typeString = callSite.Callee().Type().String()
				}
				logger.Printf(format.Red(fmt.Sprintf("| %s has not been summarized (call %s).",
					callSite.String(), typeString)))
				if callSite.Callee() != nil && callSite.CallSite() != nil {
					logger.Printf(fmt.Sprintf("| Please add %s to summaries", callSite.Callee().String()))
					logger.Printf(fmt.Sprintf("|_ See call site: %s", callSite.Position()))
				}
				break
			}
			if !callSite.CalleeSummary.Constructed {
				logger.Printf("| %s: summary has not been built for %s.",
					format.Yellow("WARNING"),
					format.Yellow(elt.Node.Graph().Parent.Name()))
				logger.Printf(fmt.Sprintf("|_ See call site: %s", callSite.Position()))
			}

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				x := callSite.CalleeSummary.Params[param]
				addNext(dataflow.NodeWithTrace{Node: x, Trace: elt.Trace.Add(callSite)})
			} else {
				logger.Fatalf("no parameter matching argument at position %d in %s",
					graphNode.Index(), callSite.CalleeSummary.Parent.String())

			}

			// We are done with propagating to the callee's parameters. Next, we need to handle
			// the flow inside the caller function: the outgoing edges computed for the summary
			for out := range graphNode.Out() {
				addNext(dataflow.NodeWithTrace{Node: out, Trace: elt.Trace})
			}

		// This is a return node. We have reached this from any node in the return node's function.
		// The data will flow to the caller.
		// If the stack is non-empty, then the data flows to back the call site in the stack(the CallNode).
		// If the stack is empty, then the data flows back to every possible call site according to the call
		// graph.
		case *dataflow.ReturnNode:
			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if elt.Trace != nil && dataflow.MapContainsCallNode(graphNode.Graph().Callsites, elt.Trace.Call) {
				// This function was called: the value flows back to the call site only
				caller := elt.Trace.Call
				for x := range caller.Out() {
					addNext(dataflow.NodeWithTrace{Node: x, Trace: elt.Trace.Parent})
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					for x := range callSite.Out() {
						addNext(dataflow.NodeWithTrace{Node: x, Trace: nil})
					}
				}
			} else {
				logger.Printf("Return node %s does not return anywhere.\n", elt.Node.String())
			}

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *dataflow.CallNode:
			// We pop the call from the stack and continue inside the caller
			var trace *dataflow.Trace
			if elt.Trace != nil {
				trace = elt.Trace.Parent
			}
			for x := range graphNode.Out() {
				addNext(dataflow.NodeWithTrace{Node: x, Trace: trace})
			}

		// Tainting a bound variable node means that the free variable in a closure will be tainted.
		// For example:
		// 1:  x := "ok" // x is not tainted here
		// 2: f := func(s string) string { return s + x } // x is bound here
		// 3: x := source()
		// 4: sink(f("ok")) // will raise an alarm
		// The flow goes from x at line 3, to x being bound at line 2, to x the free variable
		// inside the closure definition, and finally from the return of the closure to the
		// call site of the closure inside a sink.
		// For more examples with closures, see testdata/src/taint/cross-function/closures/main.go
		case *dataflow.BoundVarNode:
			// Flows inside the function creating the closure (where makeclosure happens)
			// This is similar to the dataflow edges between arguments
			for out := range graphNode.Out() {
				addNext(dataflow.NodeWithTrace{Node: out, Trace: elt.Trace})
			}

			closureNode := graphNode.ParentNode()

			if closureNode.ClosureSummary == nil {
				var instrStr string
				if closureNode.Instr() == nil {
					instrStr = "nil instr"
				} else {
					instrStr = closureNode.Instr().String()
				}
				logger.Printf(format.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
					closureNode.String(), instrStr)))
				if closureNode.Instr() != nil {
					logger.Printf(fmt.Sprintf("| Please add closure %s to summaries",
						closureNode.Instr().Fn.String()))
					logger.Printf(fmt.Sprintf("|_ See closure: %s", closureNode.Position()))
				}
				break
			}
			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				addNext(dataflow.NodeWithTrace{Node: x, Trace: elt.Trace})
			} else {
				logger.Fatalf("no free variable matching bound variable at position %d in %s",
					graphNode.Index(), closureNode.ClosureSummary.Parent.String())
			}

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		case *dataflow.FreeVarNode:
			// Flows inside the function
			for out := range graphNode.Out() {
				addNext(dataflow.NodeWithTrace{Node: out, Trace: elt.Trace})
			}

			// TODO: back flows when the free variables are tainted by the closure's body

		// A closure node can be reached if a function value is tainted
		// TODO: add an example
		case *dataflow.ClosureNode:
			for out := range graphNode.Out() {
				addNext(dataflow.NodeWithTrace{Node: out, Trace: elt.Trace})
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only need to follow the
		// outgoing edges. This node should only be a start node, unless some functionality is added to the dataflow
		// graph summaries.
		case *dataflow.SyntheticNode:
			for x := range graphNode.Out() {
				addNext(dataflow.NodeWithTrace{Node: x, Trace: elt.Trace})
			}
		}
	}
}

// addNewPathCandidate adds a new path between a source and a sink to paths using the information in elt
// returns true if it adds a new path.
// @requires elt.Node.IsSink()
func addNewPathCandidate(paths dataflow.DataFlows, source dataflow.GraphNode, sink dataflow.GraphNode) bool {
	var sourceInstr ssa.Instruction
	var sinkInstr ssa.CallInstruction

	// The source instruction depends on the type of the source: a call node or synthetic node are directly
	// related to an instruction, whereas the instruction of a call node argument is the instruction of its
	// parent call node.
	switch node := source.(type) {
	case *dataflow.CallNode:
		sourceInstr = node.CallSite()
	case *dataflow.CallNodeArg:
		sourceInstr = node.ParentNode().CallSite()
	case *dataflow.SyntheticNode:
		sourceInstr = node.Instr()
	}

	// Similar thing for the sink. Synthetic nodes are currently not used as potential sinks.
	switch node := sink.(type) {
	case *dataflow.CallNode:
		sinkInstr = node.CallSite()
	case *dataflow.CallNodeArg:
		sinkInstr = node.ParentNode().CallSite()
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
