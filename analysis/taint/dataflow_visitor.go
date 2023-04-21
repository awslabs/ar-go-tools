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

package taint

import (
	"fmt"
	"io"
	"strings"

	df "github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/format"
	"golang.org/x/tools/go/ssa"
)

// Visitor represents a taint flow visitor that tracks taint flows from sources to sinks.
type Visitor struct {
	Taints         TaintFlows
	coverageWriter io.StringWriter
}

func NewVisitor(coverageWriter io.StringWriter) *Visitor {
	return &Visitor{Taints: make(TaintFlows), coverageWriter: coverageWriter}
}

// Visit runs a cross-function analysis to add any detected taint flow from source to a sink to v.Taints.
func (v *Visitor) Visit(c *df.Cache, entrypoint df.NodeWithTrace) {
	coverage := make(map[string]bool)
	seen := make(map[df.KeyType]bool)
	goroutines := make(map[*ssa.Go]bool)
	source := entrypoint
	que := []*df.VisitorNode{{NodeWithTrace: source, ParamStack: nil, Prev: nil, Depth: 0}}

	logger := c.Logger
	logger.Printf("\n%s NEW SOURCE %s", strings.Repeat("*", 30), strings.Repeat("*", 30))
	logger.Printf("==> Source: %s\n", format.Purple(source.Node.String()))
	logger.Printf("%s %s\n", format.Green("Found at"), source.Node.Position(c))

	numAlarms := 0

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		elt := que[0]
		que = que[1:]
		// Report coverage information for the current node
		addCoverage(c, elt, coverage)

		// If node is sink, then we reached a sink from a source, and we must log the taint flow.
		if isSink(elt.Node, c.Config) {
			if addNewPathCandidate(v.Taints, source.Node, elt.Node) {
				numAlarms++
				ReportTaintFlow(c, source, elt)
				// Stop if there is a limit on number of alarms and it has been reached.
				if c.Config.MaxAlarms > 0 && numAlarms >= c.Config.MaxAlarms {
					return
				}
			}
			// A sink does not have successors in the taint flow analysis (but other sinks can be reached
			// as there are still values flowing).
			continue
		}

		// If node is sanitizer, we don't want to propagate further
		if isSanitizer(elt.Node, c.Config) {
			logger.Printf("Sanitizer encountered: %s\n", elt.Node.String())
			logger.Printf("At: %s\n", elt.Node.Position(c))
			continue
		}

		// If the node is filtered out, we don't inspect children
		if isFiltered(elt.Node, c.Config) {
			continue
		}

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().Constructed {
			if c.Config.Verbose {
				logger.Printf("%s: summary has not been built for %s.",
					format.Yellow("WARNING"),
					format.Yellow(elt.Node.Graph().Parent.Name()))
			}
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
		case *df.ParamNode:
			if elt.Prev.Node.Graph() != graphNode.Graph() {
				// Flows inside the function body. The data propagates to other locations inside the function body
				for out, oPath := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
				}
			}

			// Then we take care of the flows that go back to the callsite of the current function.
			// for example:
			// func f(s string, s2 *string) { *s2 = s }
			// The data can propagate from s to s2: we visit s from a callsite f(tainted, next), then
			// visit the parameter s2, and then next needs to be visited by going back to the callsite.
			if callSite := df.UnwindCallstackFromCallee(graphNode.Graph().Callsites, elt.Trace); callSite != nil {
				if err := checkIndex(c, graphNode, callSite, "[Unwinding callstack] Argument at call site"); err != nil {
					c.AddError("unwinding call stack at "+graphNode.Position(c).String(), err)
				} else {
					// Follow taint on matching argument at call site
					arg := callSite.Args()[graphNode.Index()]
					if arg != nil {
						que = addNext(c, que, seen, elt, arg, df.ObjectPath{}, elt.Trace.Parent, elt.ClosureTrace)
					}
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					if err := checkIndex(c, graphNode, callSite, "[No Context] Argument at call site"); err != nil {
						c.AddError("argument at call site "+graphNode.String(), err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						for x, oPath := range callSiteArg.Out() {
							que = addNext(c, que, seen, elt, x, oPath, nil, elt.ClosureTrace)
						}
					}
				}
			}

		// This is a call site argument. We have reached this either returning from a call, from the callee's parameter
		// node, or we reached this inside a function from another node.
		// In either case, the flow continues inside the function to the graphNode.Out() children and to the callee's
		// parameters
		case *df.CallNodeArg:
			// Flow to next call
			callSite := graphNode.ParentNode()

			checkNoGoRoutine(c, goroutines, callSite)

			if callSite.CalleeSummary == nil { // this function has not been summarized
				printMissingSummaryMessage(c, callSite)
				break
			}

			if !callSite.CalleeSummary.Constructed {
				printWarningSummaryNotConstructed(c, callSite)
			}

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				x := callSite.CalleeSummary.Params[param]
				que = addNext(c, que, seen, elt, x, df.ObjectPath{}, elt.Trace.Add(callSite), elt.ClosureTrace)
			} else {
				c.AddError(
					fmt.Sprintf("no parameter matching argument at in %s", callSite.CalleeSummary.Parent.String()),
					fmt.Errorf("position %d", graphNode.Index()))
			}

			if elt.Prev == nil || callSite.Graph() != elt.Prev.Node.Graph() {
				// We are done with propagating to the callee's parameters. Next, we need to handle
				// the flow inside the caller function: the outgoing edges computed for the summary
				for out, oPath := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
				}
			}

		// This is a return node. We have reached this from any node in the return node's function.
		// The data will flow to the caller.
		// If the stack is non-empty, then the data flows to back the call site in the stack(the CallNode).
		// If the stack is empty, then the data flows back to every possible call site according to the call
		// graph.
		case *df.ReturnNode:
			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if caller := df.UnwindCallstackFromCallee(graphNode.Graph().Callsites, elt.Trace); caller != nil {
				for x, oPath := range caller.Out() {
					que = addNext(c, que, seen, elt, x, oPath, elt.Trace.Parent, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil && checkClosureReturns(graphNode, elt.ClosureTrace.Label) {
				for cCall, oPath := range elt.ClosureTrace.Label.Out() {
					que = addNext(c, que, seen, elt, cCall, oPath, elt.Trace, elt.ClosureTrace.Parent)
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					for x, oPath := range callSite.Out() {
						que = addNext(c, que, seen, elt, x, oPath, nil, elt.ClosureTrace)
					}
				}
			}

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *df.CallNode:
			checkNoGoRoutine(c, goroutines, graphNode)
			// We pop the call from the stack and continue inside the caller
			var trace *df.NodeTree[*df.CallNode]
			if elt.Trace != nil {
				trace = elt.Trace.Parent
			}
			for x, oPath := range graphNode.Out() {
				que = addNext(c, que, seen, elt, x, oPath, trace, elt.ClosureTrace)
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
		case *df.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the df edges between arguments
			for out, oPath := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
			}

			closureNode := graphNode.ParentNode()

			if closureNode.ClosureSummary == nil {
				printMissingClosureNodeSummaryMessage(c, closureNode)
				break
			}
			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				que = addNext(c, que, seen, elt, x, df.ObjectPath{},
					elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				c.AddError(
					fmt.Sprintf("no free variable matching bound variable in %s",
						closureNode.ClosureSummary.Parent.String()),
					fmt.Errorf("at position %d", graphNode.Index()))
			}

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		case *df.FreeVarNode:
			// Flows inside the function
			if elt.Prev.Node.Graph() != graphNode.Graph() {
				for out, oPath := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil {
				bvs := elt.ClosureTrace.Label.BoundVars()
				if graphNode.Index() < len(bvs) {
					bv := bvs[graphNode.Index()]
					que = addNext(c, que, seen, elt, bv, df.ObjectPath{}, elt.Trace, elt.ClosureTrace.Parent)
				} else {
					c.AddError(
						fmt.Sprintf("no bound variable matching free variable in %s",
							elt.ClosureTrace.Label.ClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
				}
			} else {
				for _, makeClosureSite := range graphNode.Graph().ReferringMakeClosures {
					bvs := makeClosureSite.BoundVars()
					if graphNode.Index() < len(bvs) {
						bv := bvs[graphNode.Index()]
						que = addNext(c, que, seen, elt, bv, df.ObjectPath{}, elt.Trace, nil)
					} else {
						c.AddError(
							fmt.Sprintf("no bound variable matching free variable in %s",
								makeClosureSite.ClosureSummary.Parent.String()),
							fmt.Errorf("at position %d", graphNode.Index()))
					}

				}
			}

		// A closure node can be reached if a function value is tainted
		// TODO: add an example
		case *df.ClosureNode:
			for out, oPath := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only need to follow the
		// outgoing edges. This node should only be a start node, unless some functionality is added to the df
		// graph summaries.
		case *df.SyntheticNode:
			for x, oPath := range graphNode.Out() {
				que = addNext(c, que, seen, elt, x, oPath, elt.Trace, elt.ClosureTrace)
			}

		case *df.AccessGlobalNode:
			if graphNode.IsWrite {
				// Tainted data is written to ALL locations where the global is read.
				for x := range graphNode.Global.ReadLocations {
					// Global jump makes trace irrelevant if we don't follow the call graph!
					que = addNext(c, que, seen, elt, x, df.ObjectPath{}, nil, elt.ClosureTrace)
				}
			} else {
				// From a read location, tainted data follows the out edges of the node
				for out, oPath := range graphNode.Out() {
					que = addNext(c, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
				}
			}

		// A BoundLabel flows to the body of the closure that captures it.
		case *df.BoundLabelNode:
			closureSummary := graphNode.DestClosure()
			if closureSummary == nil {
				printMissingClosureSummaryMessage(c, graphNode)
				break
			}
			closureNode := closureSummary.ReferringMakeClosures[graphNode.DestInfo().MakeClosure]
			if closureNode == nil {
				printMissingClosureNodeSummaryMessage(c, closureNode)
				break
			}
			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureSummary.FreeVars[fv]
				que = addNext(c, que, seen, elt, x, df.ObjectPath{}, elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				c.AddError(
					fmt.Sprintf("no free variable matching bound variable in %s", closureSummary.Parent.String()),
					fmt.Errorf("at position %d", graphNode.Index()))
			}
		}
	}

	if v.coverageWriter != nil {
		reportCoverage(coverage, v.coverageWriter)
	}
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
func addNext(c *df.Cache,
	que []*df.VisitorNode,
	seen map[df.KeyType]bool,
	cur *df.VisitorNode,
	node df.GraphNode,
	edgeInfo df.ObjectPath,
	trace *df.NodeTree[*df.CallNode],
	closureTrace *df.NodeTree[*df.ClosureNode]) []*df.VisitorNode {

	// Check for validators
	if edgeInfo.Cond != nil && len(edgeInfo.Cond.Conditions) > 0 {
		for _, condition := range edgeInfo.Cond.Conditions {
			if condition.Positive && isValidatorCondition(condition.Value, c.Config) {
				c.Logger.Printf("Validated %s.\n", condition)
				return que
			}
		}
	}

	newNode := df.NodeWithTrace{Node: node, Trace: trace, ClosureTrace: closureTrace}

	// Stop conditions: node is already in seen, trace is a lasso or depth exceeds limit
	if seen[newNode.Key()] || trace.IsLasso() || cur.Depth > c.Config.MaxDepth {
		return que
	}

	// logic for parameter stack
	pStack := cur.ParamStack
	switch curNode := cur.Node.(type) {
	case *df.ReturnNode:
		pStack = pStack.Parent()
	case *df.ParamNode:
		pStack = pStack.Add(curNode)
	}

	newVis := &df.VisitorNode{
		NodeWithTrace: newNode,
		ParamStack:    pStack,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	que = append(que, newVis)
	seen[newNode.Key()] = true
	return que
}

// checkIndex checks that the indexed graph node is valid in the parent node call site
func checkIndex(c *df.Cache, node df.IndexedGraphNode, callSite *df.CallNode, msg string) error {
	if node.Index() >= len(callSite.Args()) {
		callsitePos := callSite.Position(c)
		nodePos := node.ParentNode().Position(c)
		c.Logger.Printf("%s: trying to access index %d of %s, which has only %d elements\n"+
			"See callsite: %s\n"+
			"See parent  : %s\n",
			msg, node.Index(), callSite.String(), len(callSite.Args()),
			callsitePos, nodePos)
		c.Logger.Printf("Node: %s[%d]\n", node.ParentNode().String(), node.Index())
		return fmt.Errorf("bad index %d at %s", node.Index(), callsitePos)
	}
	return nil
}

func checkClosureReturns(returnNode *df.ReturnNode, closureNode *df.ClosureNode) bool {
	if returnNode.Graph() == closureNode.ClosureSummary {
		return true
	}
	return false
}

func checkNoGoRoutine(c *df.Cache, reportedLocs map[*ssa.Go]bool, node *df.CallNode) {
	if goroutine, isGo := node.CallSite().(*ssa.Go); isGo {
		if !reportedLocs[goroutine] {
			reportedLocs[goroutine] = true
			c.Logger.Printf(format.Yellow("WARNING: Data flows to Go call."))
			c.Logger.Printf("-> Position: %s", node.Position(c))
		}
	}
}

// addNewPathCandidate adds a new path between a source and a sink to paths using the information in elt
// returns true if it adds a new path.
// @requires elt.Node.IsSink()
func addNewPathCandidate(paths TaintFlows, source df.GraphNode, sink df.GraphNode) bool {
	var sourceInstr ssa.Instruction
	var sinkInstr ssa.CallInstruction

	// The source instruction depends on the type of the source: a call node or synthetic node are directly
	// related to an instruction, whereas the instruction of a call node argument is the instruction of its
	// parent call node.
	switch node := source.(type) {
	case *df.CallNode:
		sourceInstr = node.CallSite()
	case *df.CallNodeArg:
		sourceInstr = node.ParentNode().CallSite()
	case *df.SyntheticNode:
		sourceInstr = node.Instr()
	}

	// Similar thing for the sink. Synthetic nodes are currently not used as potential sinks.
	switch node := sink.(type) {
	case *df.CallNode:
		sinkInstr = node.CallSite()
	case *df.CallNodeArg:
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