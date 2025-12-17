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

package dataflow

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// FuncInputVisitor is a data flow Visitor that computes the data flows from an input to a function
// inter-procedurally.
// The entrypoint is an input (parameter) to the function.
// If you run the Visit method on every input to the function you want to summarize, then the
// summary of that function will be complete (sound).
//
// # NOTE This does not track flows to boolean operators that short-circuit.
//
// FuncInputVisitor implements the dataflow.Visitor interface.
type FuncInputVisitor struct {
	flows   []GraphNode // flows is the data flows from function input to outputs
	entry   NodeWithTrace
	visited map[*CallStack]bool
	alarms  map[token.Pos]string
	seen    map[KeyType]bool
}

// NewFuncInputVisitor constructs a visitor to compute data flows from param inside the function.
func NewFuncInputVisitor() *FuncInputVisitor {
	return &FuncInputVisitor{
		entry:   NodeWithTrace{},
		visited: make(map[*CallStack]bool),
		alarms:  make(map[token.Pos]string),
		seen:    make(map[KeyType]bool),
	}
}

// Flows returns the data flows from function input (entrypoint) to outputs (values).
func (v *FuncInputVisitor) Flows() []GraphNode {
	return v.flows
}

// ErrGlobal is the error returned when there is data flow to a global.
var ErrGlobal = errors.New("data flow to global")

// Visit adds data flow information from entry to the inter-procedural data flow graph.
//
//gocyclo:ignore
func (v *FuncInputVisitor) Visit(ctx context.Context, s *State, entry NodeWithTrace) {
	entryParam, ok := entry.Node.(*ParamNode)
	if !ok {
		s.Report.AddError("", fmt.Errorf("entrypoint to FunctionVisitor is not a ParamNode: %v (%T)", entry.Node, entry.Node))
		return
	}

	v.entry = entry
	v.seen = make(map[KeyType]bool)

	goroutines := make(map[*ssa.Go]bool)
	logger := s.Logger
	logger.Debugf("")
	logger.Debugf(" entrypoint: %s\n",
		formatutil.Blue(v.entry.Node.String()))
	logger.Debugf("   %s %s\n", formatutil.Green("Found at"), v.entry.Node.Position(s))

	logger.PushContext(formatutil.Faint(v.entry.Node.LongID()))
	defer logger.PopContext()

	entryNode := &VisitorNode{
		NodeWithTrace: entry,
		AccessPaths:   []string{""},
		Prev:          nil,
		Depth:         0,
		Status:        VisitorNodeStatus{Kind: DefaultTracing},
	}

	que := []*VisitorNode{}
	// First initialize the analysis by visiting all outgoing edges of the parameter
	for nextNode, edgeInfos := range entry.Node.Out() {
		for _, edgeInfo := range edgeInfos {
			nextNodeWithTrace := NodeWithTrace{
				Node:         nextNode,
				Trace:        nil,
				ClosureTrace: nil,
			}
			que = v.addNext(s, que, entryNode, nil, nextNodeWithTrace, entryNode.Status, edgeInfo)
		}
	}

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		cur := que[0]
		que = que[1:]
		traceNode(s, cur)

		// Check that the node does not correspond to a non-constructed summary
		if !cur.Node.Graph().Constructed {
			// If on-demand summarization is enabled, build the summary and set the node's summary to point to the
			// built summary
			v.onDemandIntraProcedural(ctx, s, cur.Node.Graph())
		}
		if cur.Node.Graph().IsPreSummarized {
			panic(fmt.Errorf("pre-summarized summary for node %v", cur))
		}

		switch graphNode := cur.Node.(type) {

		// This is a parameter node. We have reached this node either from a function call and the stack is non-empty,
		// or we reached this node from another flow inside the function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		//- if the stack is empty, there is no calling context. The flow goes back to every possible call site of
		// the function's parameter.
		case *ParamNode:
			if cur.Prev != nil && cur.Prev.Node != nil {
				callArg, prevIsCallArg := cur.Prev.Node.(*CallNodeArg)
				if cur.Prev.Node.Graph() != graphNode.Graph() || (prevIsCallArg &&
					callArg.ParentNode().Callee() == graphNode.Graph().Parent) {
					// Flows inside the function body. The data propagates to other locations inside the function body
					// Second part of the condition allows self-recursive calls to be used
					for nextNode, edgeInfos := range graphNode.Out() {
						for _, edgeInfo := range edgeInfos {
							nextNodeWithTrace := NodeWithTrace{
								Node:         nextNode,
								Trace:        cur.Trace,
								ClosureTrace: cur.ClosureTrace,
							}
							que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
						}
					}
				}
			}

			// Then we take care of the flows that go back to the callsite of the current function.
			// for example:
			// func f(s string, s2 *string) { *s2 = s }
			// The data can propagate from s to s2: we visit s from a callsite f(tainted, next), then
			// visit the parameter s2, and then next needs to be visited by going back to the callsite.
			if callSite := UnwindCallstackFromCallee(graphNode.Graph().Callsites, cur.Trace); callSite != nil {
				err := CheckIndex(s, graphNode, callSite, "[Unwinding callstack] Argument at call site")
				if err != nil {
					s.Report.AddError("unwinding call stack at "+graphNode.Position(s).String(), err)
				} else {
					// Follow taint on matching argument at call site
					nextNodeArg := callSite.Args()[graphNode.Index()]
					if nextNodeArg != nil {
						nextNodeWithTrace := NodeWithTrace{
							Node:         nextNodeArg,
							Trace:        cur.Trace.Parent(),
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, EdgeInfo{})
					}
				}
			} else {
				// If the callstack is empty and the parameter is of the same function as the entrypoint,
				// then we stop analyzing further
				if graphNode.parent.Parent == entryParam.parent.Parent {
					s.Logger.Tracef("no callstack and parameter is entrypoint: dataflow from parameter is complete\n")
					v.addFlow(graphNode)
					continue
				}

				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					err := CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site")
					if err != nil {
						s.Report.AddError("argument at call site "+graphNode.String(), err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						if !callSiteArg.Graph().Constructed {
							v.onDemandIntraProcedural(ctx, s, callSiteArg.Graph())
						}
						for nextNode, edgeInfos := range callSiteArg.Out() {
							for _, edgeInfo := range edgeInfos {
								nextNodeWithTrace := NodeWithTrace{
									Node:         nextNode,
									Trace:        nil,
									ClosureTrace: cur.ClosureTrace,
								}
								que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
							}
						}
					}
				}
			}

		// This is a call site argument. We have reached this either returning from a call, from the callee's parameter
		// node, or we reached this inside a function from another node.
		// In either case, the flow continues inside the function to the graphNode.Out() children and to the callee's
		// parameters
		case *CallNodeArg:
			// Flow to next call
			callSite := graphNode.ParentNode()

			CheckNoGoRoutine(s, goroutines, callSite)

			// Logic for when the summary has not been created
			if callSite.CalleeSummary == nil {
				if callSite.Callee() == nil {
					panic("callsite has no callee")
				}
				callSite.CalleeSummary = NewSummaryGraph(s, callSite.Callee(), GetUniqueFunctionID(), nil, nil)
			}
			// callSiteFromCallStack.CalleeSummary should be non-nil from now on in this branch.

			// Logic for when the summary has not been constructed
			if !callSite.CalleeSummary.Constructed {
				v.onDemandIntraProcedural(ctx, s, callSite.CalleeSummary)
			}

			// Computing context-sensitive information for the analyses

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				// This is where a function gets "called" and the next nodes will be analyzed in a different context
				nextNode := callSite.CalleeSummary.Params[param]

				newCallStack := cur.Trace.Add(callSite)
				v.visited[newCallStack] = true
				nextNodeWithTrace := NodeWithTrace{
					Node:         nextNode,
					Trace:        newCallStack,
					ClosureTrace: cur.ClosureTrace,
				}
				que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, EdgeInfo{})
			} else {
				s.Report.AddError(
					fmt.Sprintf("no parameter matching argument at in %s", callSite.CalleeSummary.Parent.String()),
					fmt.Errorf("position %d", graphNode.Index()))
				panic("nil param")
			}

			if cur.Prev == nil || callSite.Graph() != cur.Prev.Node.Graph() {
				// We are done with propagating to the callee's parameters. Next, we need to handle
				// the flow inside the caller function: the outgoing edges computed for the summary
				for nextNode, edgeInfos := range graphNode.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			}

		// This is a return node. We have reached this from any node in the return node's function.
		// The data will flow to the caller.
		// If the stack is non-empty, then the data flows to back the call site in the stack(the CallNode).
		// If the stack is empty, then the data flows back to every possible call site according to the call
		// graph.
		case *ReturnValNode:
			// If the return node is a return of the parameter's function, then stop analyzing further
			if graphNode.parent.Parent == entryParam.ssaNode.Parent() {
				s.Logger.Tracef("dataflow from return is complete")
				v.addFlow(graphNode)
				continue
			}

			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if callSiteFromCallStack := UnwindCallstackFromCallee(graphNode.Graph().Callsites, cur.Trace); callSiteFromCallStack != nil {
				logger.Tracef("unwound caller: %v\n", callSiteFromCallStack)
				if !callSiteFromCallStack.Graph().Constructed {
					v.onDemandIntraProcedural(ctx, s, callSiteFromCallStack.Graph())
				}
				for nextNode, edgeInfos := range callSiteFromCallStack.Out() {
					for _, edgeInfo := range edgeInfos {
						if !(graphNode.Index() >= 0 && edgeInfo.Index >= 0 && graphNode.Index() != edgeInfo.Index) {
							nextNodeWithTrace := NodeWithTrace{
								Node:         nextNode,
								Trace:        cur.Trace.Parent(),
								ClosureTrace: cur.ClosureTrace,
							}
							que = v.addNext(s, que, cur, callSiteFromCallStack, nextNodeWithTrace, cur.Status, edgeInfo)
						}
					}
				}
			} else if cur.ClosureTrace != nil && CheckClosureReturns(graphNode, cur.ClosureTrace.Label) {
				if !cur.ClosureTrace.Label.Graph().Constructed {
					v.onDemandIntraProcedural(ctx, s, cur.ClosureTrace.Label.Graph())
				}
				for nextNode, edgeInfos := range cur.ClosureTrace.Label.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace.Parent(),
						}
						que = v.addNext(s, que, cur, cur.ClosureTrace.Label, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					if !callSite.Graph().Constructed {
						v.onDemandIntraProcedural(ctx, s, callSite.Graph())
					}
					for nextNode, edgeInfos := range callSite.Out() {
						for _, edgeInfo := range edgeInfos {
							nextNodeWithTrace := NodeWithTrace{
								Node:         nextNode,
								Trace:        nil,
								ClosureTrace: cur.ClosureTrace,
							}
							que = v.addNext(s, que, cur, callSite, nextNodeWithTrace, cur.Status, edgeInfo)
						}
					}
				}
			}
			// else, if there are no callsites this was an unreachable function

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *CallNode:
			CheckNoGoRoutine(s, goroutines, graphNode)

			if cur.Status.Kind == ClosureTracing {
				if graphNode.CalleeSummary != nil &&
					// the following equality being true must imply that graphNode.CalleeSummary is a closure's summary
					graphNode.CalleeSummary == cur.Status.CurrentClosure() {
					fv := cur.Status.CurrentClosure().Parent.FreeVars[cur.Status.TracingInfo.Index]

					if fv != nil {
						nextNodeWithTrace := NodeWithTrace{
							Node:         graphNode.CalleeSummary.FreeVars[fv],
							Trace:        cur.Trace.Add(graphNode),
							ClosureTrace: cur.ClosureTrace,
						}

						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status.PopClosure(), EdgeInfo{})
					} else {
						s.Report.AddError(
							fmt.Sprintf("no free variable matching bound variable in %s",
								graphNode.CalleeSummary.Parent.String()),
							fmt.Errorf("at position %d", cur.Status.TracingInfo.Index))
					}
				}
			}
			// We pop the call from the stack and continue inside the caller
			var trace *NodeTree[*CallNode]
			if cur.Trace != nil {
				trace = cur.Trace.Parent()
			}
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := NodeWithTrace{
						Node:         nextNode,
						Trace:        trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

			// If the call is an entrypoint node, the actual entrypoint node may be one of its arguments
			// See the closures_paper test for an example
			if graphNode == entry.Node {
				for _, arg := range graphNode.Args() {
					nextNodeWithTrace := NodeWithTrace{
						Node:         arg,
						Trace:        trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, EdgeInfo{})
				}
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
		case *BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the df edges between arguments
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

			closureNode := graphNode.ParentNode()

			if !closureNode.IsReachable(s) {
				break
			}

			if closureNode.ClosureSummary == nil {
				closureNode.ClosureSummary = NewSummaryGraph(s, closureNode.parent.Parent, GetUniqueFunctionID(), nil, nil)
			}
			if !closureNode.ClosureSummary.Constructed {
				v.onDemandIntraProcedural(ctx, s, closureNode.ClosureSummary)
				s.FlowGraph.Sync()
			}

			closureNodeWithTrace := NodeWithTrace{
				Node:         closureNode,
				Trace:        UnwindCallStackToFunc(cur.Trace, closureNode.Graph().Parent),
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}

			que = v.addNext(s, que, cur, nil, closureNodeWithTrace,
				VisitorNodeStatus{
					Kind:        ClosureTracing,
					TracingInfo: cur.Status.TracingInfo.Next(closureNode.ClosureSummary, graphNode.Index()),
				},
				EdgeInfo{})

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		// The date can also flow from the function body to the free var node, in which case it implies the bound
		// variable (in the caller) is tainted after the function returns.
		case *FreeVarNode:
			// Flows inside the function
			if cur.Prev == nil || (cur.Prev.Node.Graph() != graphNode.Graph()) {
				for nextNode, edgeInfos := range graphNode.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			} else if cur.ClosureTrace != nil {
				bvs := cur.ClosureTrace.Label.BoundVars()
				if len(bvs) == 0 {
					panic("no bound vars")
				}
				if graphNode.Index() < len(bvs) {
					bv := bvs[graphNode.Index()]
					nextNodeWithTrace := NodeWithTrace{
						Node:         bv,
						Trace:        cur.Trace.Parent(),
						ClosureTrace: cur.ClosureTrace.Parent(),
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, EdgeInfo{})
				} else {
					s.Report.AddError(
						fmt.Sprintf("no bound variable matching free variable in %s",
							cur.ClosureTrace.Label.ClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
					panic(fmt.Errorf("no bound variable matching free variable in %s at position %d",
						cur.ClosureTrace.Label.ClosureSummary.Parent.String(), graphNode.Index()))
				}
			} else {
				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					// Summarize the free variable's closure's parent function if there is one
					f := graphNode.Graph().Parent.Parent()
					if !s.IsReachableFunction(f) {
						// we're not even in a reachable function, so the data cannot be flowing here
						// we might have reached this point by moving throught bound variables/global variables
						// but the function is not actually reachable.
						break
					}
					if f != nil {
						BuildSummary(s, f)
					}
					// This is needed to get the referring make closures outside the function
					s.FlowGraph.Sync()
				}

				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					panic(fmt.Errorf("[No Context] no referring make closure nodes from %v", graphNode))
				}

				for _, makeClosureSite := range graphNode.Graph().ReferringMakeClosures {
					bvs := makeClosureSite.BoundVars()
					if graphNode.Index() < len(bvs) {
						nextNodeWithTrace := NodeWithTrace{
							Node:         bvs[graphNode.Index()],
							Trace:        cur.Trace,
							ClosureTrace: nil,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, EdgeInfo{})
					} else {
						panicOnUnexpectedMissingFreeVar(s, makeClosureSite, graphNode)
					}
				}
			}

		// A closure node is usually reached when the visitor is tracing a specific closure
		case *ClosureNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only need to follow the
		// outgoing edges. This node should only be a start node, unless some functionality is added to the df
		// graph summaries.
		case *SyntheticNode, *BuiltinCallNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

		case *AccessGlobalNode:
			// TODO For now, analyzing a function with globals results in an error
			s.Report.AddError("", fmt.Errorf("%w in function %v with trace %s", ErrGlobal, graphNode.graph.Parent.String(), cur.Trace.SummaryString()))
			return

		// A BoundLabel flows to the body of the closure that captures it.
		case *BoundLabelNode:
			destClosureSummary := graphNode.DestClosure()
			if destClosureSummary == nil {
				closureFn := graphNode.DestInfo().MakeClosure.Fn.(*ssa.Function)
				// The function that created the closure is not reachable, so it can't be the case
				// that the data would flow from that closure creation site.
				if !s.IsReachableFunction(closureFn) {
					break
				}
				destClosureSummary = BuildSummary(s, closureFn)
				graphNode.SetDestClosure(destClosureSummary)
				s.FlowGraph.Sync()
			}

			if len(destClosureSummary.ReferringMakeClosures) == 0 {
				panic(fmt.Errorf("[No Context] no referring make closure nodes from %v", graphNode))
			}

			closureNode := destClosureSummary.ReferringMakeClosures[graphNode.DestInfo().MakeClosure]
			if closureNode == nil {
				logger.Warnf("Missing closure node for bound label %v at %v\n", graphNode, graphNode.Position(s))
				break
			}
			if !closureNode.IsReachable(s) {
				break
			}

			closureNodeWithTrace := NodeWithTrace{
				Node:         closureNode,
				Trace:        UnwindCallStackToFunc(cur.Trace, closureNode.Graph().Parent),
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}

			que = v.addNext(s, que, cur, nil, closureNodeWithTrace,
				VisitorNodeStatus{
					Kind:        ClosureTracing,
					TracingInfo: cur.Status.TracingInfo.Next(closureNode.ClosureSummary, graphNode.Index()),
				},
				EdgeInfo{})

		case *IfNode:
			// Don't track data flow inside of conditionals
			break

		default:
			panic(fmt.Sprintf("unhandled node type: %T", graphNode))
		}
	}
}

// onDemandIntraProcedural runs the intra-procedural on the summary, modifying its state
// This panics when the analysis fails, because it is expected that an error will cause any further result
// to be invalid.
func (v *FuncInputVisitor) onDemandIntraProcedural(ctx context.Context, s *State, summary *SummaryGraph) {
	s.Logger.Debugf("[On-demand] Summarizing %s...", summary.Parent)
	elapsed, err := RunIntraProcedural(ctx, s, summary)
	s.Logger.Debugf("%-12s %-90s [%.2f s]\n", " ", summary.Parent.String(), elapsed.Seconds())
	if err != nil {
		panic(fmt.Sprintf("failed to run intra-procedural analysis : %v", err))
	}
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
//
// - que is the DFS/BFS queue in the calling algorithm
//
// - cur is the current visitor node
//
// - intermediate is an intermediate node to be inserted for tracing purposes
//
// - nextNodeWithTrace is the graph node to add to the queue, with the new call stack trace and closure stack trace
//
// - nextMode is the mode for the next node that will be added
//
// - edgeInfo is the label of the edge from cur's node to toAdd
//
//gocyclo:ignore
func (v *FuncInputVisitor) addNext(s *State,
	que []*VisitorNode,
	cur *VisitorNode,
	intermediateNode GraphNode,
	nextNodeWithTrace NodeWithTrace,
	nextStatus VisitorNodeStatus,
	edgeInfo EdgeInfo) []*VisitorNode {

	if len(cur.AccessPaths) == 0 {
		panic("access paths should always at least be the empty string")
	}

	nextNodeAccessPaths := []string{}
	for inPath, outPaths := range edgeInfo.RelPath {
		for outPath := range outPaths {
			// Logic for matching paths
			for _, ap := range cur.AccessPaths {
				if strings.HasPrefix(inPath, ap) {
					nextNodeAccessPaths = append(nextNodeAccessPaths, outPath)
				}
			}
		}
	}
	if len(edgeInfo.RelPath) == 0 || len(edgeInfo.RelPath) == 1 && edgeInfo.RelPath[""][""] {
		nextNodeAccessPaths = cur.AccessPaths
	}
	if len(edgeInfo.RelPath) == 1 && edgeInfo.RelPath["*"][""] {
		nextNodeAccessPaths = []string{""}
	}
	// No matching access paths for this edge
	if len(nextNodeAccessPaths) == 0 {
		return que
	}

	// Insert intermediate node for tracing when intermediateNode is not nil
	// The information (status, accesspaths) can be incorrect and the analysis will still be sound in the sense
	// that a taint flow will be reported, but the information may be inaccurate.
	// The next node is used to fill in the information.
	prevNode := cur
	if intermediateNode != nil {
		prevNode = &VisitorNode{
			NodeWithTrace: NodeWithTrace{
				Node:         intermediateNode,
				Trace:        nextNodeWithTrace.Trace,
				ClosureTrace: nextNodeWithTrace.ClosureTrace,
			},
			Prev:        cur,
			Depth:       cur.Depth + 1,
			AccessPaths: nextNodeAccessPaths,
			Status:      nextStatus,
		}
	}

	// Adding the next node with trace in a visitor node to the queue, and recording the "execution" tree
	nextVisitorNode := &VisitorNode{
		NodeWithTrace: nextNodeWithTrace,
		AccessPaths:   nextNodeAccessPaths,
		Status:        nextStatus,
		Prev:          prevNode,
		Depth:         cur.Depth + 1,
	}

	// First set of stop conditions: node has already been seen, or depth exceeds limit
	nodeKey := nextVisitorNode.Key()
	alreadySeen := v.seen[nodeKey]
	exceedsDepth := s.Config.ExceedsMaxDepth(cur.Depth)

	if alreadySeen || exceedsDepth {
		return que
	}

	// Second set of stopping conditions: the calling context is unchanged on a loop path
	if nextNodeWithTrace.Trace.GetLassoHandle() != nil || nextNodeWithTrace.ClosureTrace.GetLassoHandle() != nil {
		return que
	}

	cur.AddChild(nextVisitorNode)
	que = append(que, nextVisitorNode)
	v.seen[nodeKey] = true

	return que
}

// addFlow adds a data flow from function input to function output.
func (v *FuncInputVisitor) addFlow(to GraphNode) {
	v.flows = append(v.flows, to)
}

// traceNodes prints trace information about the cur node.
func traceNode(s *State, cur *VisitorNode) {
	if !s.Logger.LogsTrace() {
		return
	}
	s.Logger.Tracef("(s=%v) Visiting %T node: %v\n\tat %v\n",
		cur.Status.Kind, cur.Node, cur.Node, cur.Node.Position(s))
	s.Logger.Tracef("Trace: %s\n", cur.Trace.String())
}

// panicOnUnexpectedMissingFreeVar **panics**, but adds and error to the state before.
func panicOnUnexpectedMissingFreeVar(s *State, makeClosureSite *ClosureNode, graphNode *FreeVarNode) {
	s.Report.AddError(
		fmt.Sprintf("no bound variable matching free variable in %s",
			makeClosureSite.ClosureSummary.Parent.String()),
		fmt.Errorf("at position %d", graphNode.Index()))
	panic(
		fmt.Errorf(
			"[No Context] no bound variable matching free variable in %s at position %d",
			makeClosureSite.ClosureSummary.Parent.String(), graphNode.Index()))
}
