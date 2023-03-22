package taint

import (
	"fmt"
	"io"
	"strings"

	"github.com/awslabs/argot/analysis/dataflow"
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
func (v *Visitor) Visit(c *dataflow.Cache, entrypoint dataflow.NodeWithTrace) {
	coverage := make(map[string]bool)
	seen := make(map[dataflow.NodeWithTrace]bool)
	goroutines := make(map[*ssa.Go]bool)
	source := entrypoint
	que := []*dataflow.VisitorNode{{NodeWithTrace: source, ParamStack: nil, Prev: nil, Depth: 0}}

	logger := c.Logger
	logger.Printf("\n%s NEW SOURCE %s", strings.Repeat("*", 30), strings.Repeat("*", 30))
	logger.Printf("==> Source: %s\n", format.Purple(source.Node.String()))
	logger.Printf("%s %s\n", format.Green("Found at"), source.Node.Position(c))

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// TODO: optimize call stack
	// TODO: set of visited nodes is not handled properly right now. We should revisit some nodes,
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		elt := que[0]
		que = que[1:]
		// Report coverage information for the current node
		addCoverage(c, elt, coverage)

		// If node is sink, then we reached a sink from a source, and we must log the taint flow.
		if isSink(elt.Node, c.Config) {
			if addNewPathCandidate(v.Taints, source.Node, elt.Node) {
				ReportTaintFlow(c, source, elt)
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
			if elt.Trace != nil {
				// This function was called: the value flows back to the call site only
				// TODO: check that this assumption is correct
				callSite := elt.Trace.Label
				if err := checkIndex(c, graphNode, callSite, "Argument at call site"); err != nil {
					c.AddError(err)
				} else {
					// Follow taint on matching argument at call site
					arg := callSite.Args()[graphNode.Index()]
					if arg != nil {
						que = addNext(c, que, seen, elt, arg, elt.Trace.Parent, elt.ClosureTrace)
					}
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					if err := checkIndex(c, graphNode, callSite, "Argument at call site"); err != nil {
						c.AddError(err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						for x := range callSiteArg.Out() {
							que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
						}
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
				que = addNext(c, que, seen, elt, x, elt.Trace.Add(callSite), elt.ClosureTrace)
			} else {
				c.AddError(fmt.Errorf("no parameter matching argument at position %d in %s",
					graphNode.Index(), callSite.CalleeSummary.Parent.String()))
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
		case *dataflow.ReturnNode:
			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if elt.Trace != nil && dataflow.CheckCallStackContainsCallsite(c, graphNode.Graph().Callsites, elt.Trace.Label) {
				// This function was called: the value flows back to the call site only
				caller := elt.Trace.Label
				for x := range caller.Out() {
					que = addNext(c, que, seen, elt, x, elt.Trace.Parent, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil && checkClosureReturns(graphNode, elt.ClosureTrace.Label) {
				for cCall := range elt.ClosureTrace.Label.Out() {
					que = addNext(c, que, seen, elt, cCall, elt.Trace, elt.ClosureTrace.Parent)
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					for x := range callSite.Out() {
						que = addNext(c, que, seen, elt, x, nil, elt.ClosureTrace)
					}
				}
			}

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *dataflow.CallNode:
			checkNoGoRoutine(c, goroutines, graphNode)
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
		// For more examples with closures, see testdata/src/taint/cross-function/closures/main.go
		case *dataflow.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the dataflow edges between arguments
			for out := range graphNode.Out() {
				que = addNext(c, que, seen, elt, out, elt.Trace, elt.ClosureTrace)
			}

			closureNode := graphNode.ParentNode()

			if closureNode.ClosureSummary == nil {
				printMissingClosureSummaryMessage(c, closureNode)
				break
			}
			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				que = addNext(c, que, seen, elt, x, elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				c.AddError(fmt.Errorf("no free variable matching bound variable at position %d in %s",
					graphNode.Index(), closureNode.ClosureSummary.Parent.String()))
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
					c.AddError(fmt.Errorf("no bound variable matching free variable at position %d in %s",
						graphNode.Index(), elt.ClosureTrace.Label.ClosureSummary.Parent.String()))
				}
			} else {
				for _, makeClosureSite := range graphNode.Graph().ReferringMakeClosures {
					bvs := makeClosureSite.BoundVars()
					if graphNode.Index() < len(bvs) {
						bv := bvs[graphNode.Index()]
						que = addNext(c, que, seen, elt, bv, elt.Trace, nil)
					} else {
						c.AddError(fmt.Errorf("no bound variable matching free variable at position %d in %s",
							graphNode.Index(), makeClosureSite.ClosureSummary.Parent.String()))
					}

				}
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
		}
	}

	if v.coverageWriter != nil {
		reportCoverage(coverage, v.coverageWriter)
	}
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
func addNext(c *dataflow.Cache,
	que []*dataflow.VisitorNode,
	seen map[dataflow.NodeWithTrace]bool,
	cur *dataflow.VisitorNode,
	node dataflow.GraphNode,
	trace *dataflow.NodeTree[*dataflow.CallNode],
	closureTrace *dataflow.NodeTree[*dataflow.ClosureNode]) []*dataflow.VisitorNode {

	newNode := dataflow.NodeWithTrace{Node: node, Trace: trace, ClosureTrace: closureTrace}

	// Stop conditions: node is already in seen, trace is a lasso or depth exceeds limit
	if seen[newNode] || trace.IsLasso() || cur.Depth > c.Config.MaxDepth {
		return que
	}

	// logic for parameter stack
	pStack := cur.ParamStack
	switch curNode := cur.Node.(type) {
	case *dataflow.ReturnNode:
		pStack = pStack.Parent()
	case *dataflow.ParamNode:
		pStack = pStack.Add(curNode)
	}

	newVis := &dataflow.VisitorNode{
		NodeWithTrace: newNode,
		ParamStack:    pStack,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	que = append(que, newVis)
	seen[newNode] = true
	return que
}

// checkIndex checks that the indexed graph node is valid in the parent node call site
func checkIndex(c *dataflow.Cache, node dataflow.IndexedGraphNode, callSite *dataflow.CallNode, msg string) error {
	if node.Index() >= len(callSite.Args()) {
		pos := c.Program.Fset.Position(callSite.CallSite().Value().Pos())
		c.Logger.Printf("%s: trying to access index %d of %s, which has"+
			" only %d elements\nSee: %s\n", msg, node.Index(), callSite.String(), len(callSite.Args()),
			pos)
		return fmt.Errorf("bad index %d at %s", node.Index(), pos)
	}
	return nil
}

func checkClosureReturns(returnNode *dataflow.ReturnNode, closureNode *dataflow.ClosureNode) bool {
	if returnNode.Graph() == closureNode.ClosureSummary {
		return true
	}
	return false
}

func checkNoGoRoutine(c *dataflow.Cache, reportedLocs map[*ssa.Go]bool, node *dataflow.CallNode) {
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
func addNewPathCandidate(paths TaintFlows, source dataflow.GraphNode, sink dataflow.GraphNode) bool {
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
