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

// Package render provides functions to build a inter-procedural dataflow graph.
// This is used to render the graph in a GraphViz format.
package render

import (
	"fmt"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// BuildCrossFunctionGraph builds a full-program (inter-procedural) analysis state from program.
func BuildCrossFunctionGraph(state *dataflow.State) (*dataflow.State, error) {
	if len(state.FlowGraph.Summaries) == 0 {
		return nil, fmt.Errorf("state does not contain any summaries")
	}

	state.Logger.Infof("Building full-program inter-procedural dataflow graph...")
	start := time.Now()
	dataflow.RunInterProcedural(state, CrossFunctionGraphVisitor{}, dataflow.ScanningSpec{
		IsEntryPointSsa: func(ssa.Node) bool { return true },
	})

	state.Logger.Infof("Full-program inter-procedural dataflow graph done (%.2f s).", time.Since(start).Seconds())
	return state, nil
}

// CrossFunctionGraphVisitor represents a visitor that builds the state's
// FlowGraph.
type CrossFunctionGraphVisitor struct{}

// Visit is a SourceVisitor that builds adds edges between the
// individual intra-procedural dataflow graphs reachable from source.
// This visitor must be called for every entrypoint in the program to build a
// complete dataflow graph.
//
//gocyclo:ignore
func (v CrossFunctionGraphVisitor) Visit(c *dataflow.State, entrypoint dataflow.NodeWithTrace) {
	que := []*dataflow.VisitorNode{{NodeWithTrace: entrypoint, Prev: nil, Depth: 0}}
	seen := make(map[dataflow.NodeWithTrace]bool)
	goroutines := make(map[*ssa.Go]bool)
	logger := c.Logger

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// TODO: optimize call stack
	// TODO: set of visited nodes is not handled properly right now. We should revisit some nodes,
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		elt := que[0]
		que = que[1:]

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().Constructed {

			logger.Debugf("%s: summary has not been built for %s.",
				formatutil.Yellow("WARNING"),
				formatutil.Yellow(formatutil.Sanitize(elt.Node.Graph().Parent.Name())))
			// In that case, continue as there is no information on data flow
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
			if elt.Prev.Node.Graph() != graphNode.Graph() {
				// Flows inside the function body. The data propagates to other locations inside the function body
				for out := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
				}
			}

			// Then we take care of the flows that go back to the callsite of the current function.
			// for example:
			// func f(s string, s2 *string) { *s2 = s }
			// The data can propagate from s to s2: we visit s from a callsite f(tainted, next), then
			// visit the parameter s2, and then next needs to be visited by going back to the callsite.
			if callSite := dataflow.UnwindCallstackFromCallee(graphNode.Graph().Callsites, elt.Trace); callSite != nil {
				if err := dataflow.CheckIndex(c, graphNode, callSite, "[Unwinding callstack] Argument at call site"); err != nil {
					c.Report.AddError("unwinding call stack at "+graphNode.Position(c).String(), err)
				} else {
					// Follow taint on matching argument at call site
					arg := callSite.Args()[graphNode.Index()]
					if arg != nil {
						que = addNext(c, que, seen, elt, arg, elt.Trace.Parent, elt.ClosureTrace)
						addEdge(c.FlowGraph, arg, graphNode)
					}
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					if err := dataflow.CheckIndex(c, graphNode, callSite, "[No Context] Argument at call site"); err != nil {
						c.Report.AddError("argument at call site "+graphNode.String(), err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						for x := range callSiteArg.Out() {
							que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
						}
						addEdge(c.FlowGraph, callSiteArg, graphNode)
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

			dataflow.CheckNoGoRoutine(c, goroutines, callSite)

			if callSite.CalleeSummary == nil { // this function has not been summarized
				c.ReportMissingOrNotConstructedSummary(callSite)
				break
			}

			if !callSite.CalleeSummary.Constructed {
				c.ReportSummaryNotConstructed(callSite)
			}

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				x := callSite.CalleeSummary.Params[param]
				que = addNext(c, que, seen, elt, x, elt.Trace.Add(callSite), elt.ClosureTrace)
				addEdge(c.FlowGraph, graphNode, x)
			} else {
				c.Report.AddError(
					fmt.Sprintf("no parameter matching argument in %s", callSite.CalleeSummary.Parent.String()),
					fmt.Errorf("position %d", graphNode.Index()))
			}

			if elt.Prev == nil || callSite.Graph() != elt.Prev.Node.Graph() {
				// We are done with propagating to the callee's parameters. Next, we need to handle
				// the flow inside the caller function: the outgoing edges computed for the summary
				for out := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
				}
			}

		// This is a return node. We have reached this from any node in the return node's function.
		// The data will flow to the caller.
		// If the stack is non-empty, then the data flows to back the call site in the stack(the CallNode).
		// If the stack is empty, then the data flows back to every possible call site according to the call
		// graph.
		case *dataflow.ReturnValNode:
			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if caller := dataflow.UnwindCallstackFromCallee(graphNode.Graph().Callsites, elt.Trace); caller != nil {
				// This function was called: the value flows back to the call site only
				addEdge(c.FlowGraph, graphNode, caller)
				for x := range caller.Out() {
					que = addNext(c, que, seen, elt, x, elt.Trace.Parent, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil && dataflow.CheckClosureReturns(graphNode, elt.ClosureTrace.Label) {
				addEdge(c.FlowGraph, graphNode, elt.ClosureTrace.Label)
				for cCall := range elt.ClosureTrace.Label.Out() {
					que = addNext(c, que, seen, elt, cCall, elt.Trace, elt.ClosureTrace.Parent)
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					addEdge(c.FlowGraph, graphNode, callSite)
					for x := range callSite.Out() {
						que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
					}
				}
			}

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *dataflow.CallNode:
			dataflow.CheckNoGoRoutine(c, goroutines, graphNode)
			// We pop the call from the stack and continue inside the caller
			var trace *dataflow.NodeTree[*dataflow.CallNode]
			if elt.Trace != nil {
				trace = elt.Trace.Parent
			}
			for x := range graphNode.Out() {
				que = addNext(c, que, seen, elt, x, trace, elt.ClosureTrace)
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
		// For more examples with closures, see testdata/src/taint/inter-procedural/closures/main.go
		case *dataflow.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the dataflow edges between arguments
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

			closureNode := graphNode.ParentNode()

			if closureNode.ClosureSummary == nil {
				c.ReportMissingClosureNode(closureNode)
				break
			}
			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				que = addNext(c, que, seen, elt, x, elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				c.Report.AddError(
					fmt.Sprintf("no free variable matching bound variable in %s",
						closureNode.ClosureSummary.Parent.String()),
					fmt.Errorf("at position %d", graphNode.Index()))
			}

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		case *dataflow.FreeVarNode:
			// Flows inside the function
			if elt.Prev.Node.Graph() != graphNode.Graph() {
				for out := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil {
				bvs := elt.ClosureTrace.Label.BoundVars()
				if graphNode.Index() < len(bvs) {
					bv := bvs[graphNode.Index()]
					que = addNext(c, que, seen, elt, bv, elt.Trace, elt.ClosureTrace.Parent)
				} else {
					c.Report.AddError(
						fmt.Sprintf("no bound variable matching free variable in %s",
							elt.ClosureTrace.Label.ClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
				}
			} else {
				for _, makeClosureSite := range graphNode.Graph().ReferringMakeClosures {
					bvs := makeClosureSite.BoundVars()
					if graphNode.Index() < len(bvs) {
						bv := bvs[graphNode.Index()]
						que = addNext(c, que, seen, elt, bv, elt.Trace, nil)
					} else {
						c.Report.AddError(
							fmt.Sprintf("no bound variable matching free variable in %s",
								makeClosureSite.ClosureSummary.Parent.String()),
							fmt.Errorf("at position %d", graphNode.Index()))
					}
				}
			}
			// Flows inside the function
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

		// A closure node can be reached if a function value is tainted
		// TODO: add an example
		case *dataflow.ClosureNode:
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only need to follow the
		// outgoing edges. This node should only be a start node, unless some functionality is added to the dataflow
		// graph summaries.
		case *dataflow.SyntheticNode:
			for x := range graphNode.Out() {
				que = addNext(c, que, seen, elt, x, elt.Trace, elt.ClosureTrace)
			}
		case *dataflow.AccessGlobalNode:
			global := graphNode.Global
			if accesses, ok := c.FlowGraph.Globals[global]; !ok {
				if c.FlowGraph.Globals == nil {
					c.FlowGraph.Globals = make(map[*dataflow.GlobalNode]map[*dataflow.AccessGlobalNode]bool)
				}
				c.FlowGraph.Globals[global] = map[*dataflow.AccessGlobalNode]bool{graphNode: true}
			} else {
				if accesses == nil {
					accesses = make(map[*dataflow.AccessGlobalNode]bool)
				}
				accesses[graphNode] = true
			}

			if graphNode.IsWrite {
				// Tainted data is written to ALL locations where the global is read.
				for x := range graphNode.Global.ReadLocations {
					// Global jump makes trace irrelevant if we don't follow the call graph!
					que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
				}
			} else {
				// From a read location, tainted data follows the out edges of the node
				for out := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
				}
			}
		// A BoundLabel flows to the body of the closure that captures it.
		case *dataflow.BoundLabelNode:
			closureSummary := graphNode.DestClosure()
			if closureSummary == nil {
				// printMissingClosureSummaryMessage(c, graphNode)
				break
			}
			closureNode := closureSummary.ReferringMakeClosures[graphNode.DestInfo().MakeClosure]
			if closureNode == nil {
				// printMissingClosureNodeSummaryMessage(c, closureNode)
				break
			}
			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureSummary.FreeVars[fv]
				que = addNext(c, que, seen, elt, x, elt.Trace, elt.ClosureTrace.Add(closureNode))
				addEdge(c.FlowGraph, graphNode, closureNode)
			} else {
				c.Report.AddError(
					fmt.Sprintf("no free variable matching bound variable in %s", closureSummary.Parent.String()),
					fmt.Errorf("at position %d", graphNode.Index()))
			}
		}
	}
}

// addEdge adds forward edge src -> dst and backwards edge src <- dst to graph.
func addEdge(graph *dataflow.InterProceduralFlowGraph, src dataflow.GraphNode, dst dataflow.GraphNode) {
	if _, ok := graph.ForwardEdges[src]; !ok {
		graph.ForwardEdges[src] = make(map[dataflow.GraphNode]bool)
	}
	graph.ForwardEdges[src][dst] = true

	if _, ok := graph.BackwardEdges[dst]; !ok {
		graph.BackwardEdges[dst] = make(map[dataflow.GraphNode]bool)
	}
	graph.BackwardEdges[dst][src] = true
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
func addNext(c *dataflow.State,
	que []*dataflow.VisitorNode,
	seen map[dataflow.NodeWithTrace]bool,
	cur *dataflow.VisitorNode,
	node dataflow.GraphNode,
	trace *dataflow.NodeTree[*dataflow.CallNode],
	closureTrace *dataflow.NodeTree[*dataflow.ClosureNode]) []*dataflow.VisitorNode {

	newNode := dataflow.NodeWithTrace{Node: node, Trace: trace, ClosureTrace: closureTrace}

	// Stop conditions: node is already in seen, trace is a lasso or depth exceeds limit
	if seen[newNode] || trace.GetLassoHandle() != nil || c.Config.ExceedsMaxDepth(cur.Depth) {
		return que
	}

	newVis := &dataflow.VisitorNode{
		NodeWithTrace: newNode,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	que = append(que, newVis)
	seen[newNode] = true
	return que
}
