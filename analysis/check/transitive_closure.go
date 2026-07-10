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

package check

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"slices"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
)

// FlowNode identifies a data flow graph node together with the object access path reached within
// it (e.g. ".a" for field a of a struct-typed node). Path is empty when the flow is
// field-insensitive, either because the node's type has no sub-fields or the flow was not tracked
// field-sensitively.
type FlowNode struct {
	Node dataflow.GraphNode
	Path string
}

// ClosedInterproceduralSummary is the full inter-procedurally-generated data flow summary for a function.
type ClosedInterproceduralSummary struct {
	Graph       *dataflow.SummaryGraph  // Graph is the summary graph.
	Flows       map[FlowNode][]FlowNode // Flows are from function inputs to outputs, field-sensitively.
	Unsoundness Unsoundness
}

// flowNodeToSummaryNode converts a FlowNode to a summaries.SummaryNode, preserving its access path
// as the resulting summary node's ObjectPath.
func flowNodeToSummaryNode(fn FlowNode) (sn summaries.SummaryNode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to convert graph node to summary node: %v", r)
		}
	}()
	sn = newSummaryNode(newGraphNode(fn.Node, fn.Path))
	return sn, nil
}

// ToDetailedSummary converts to a detailed summary using the string representation of the nodes instead of the
// graph nodes themselves
func (c ClosedInterproceduralSummary) ToDetailedSummary() (summaries.DetailedSummary, error) {
	flows := map[summaries.SummaryNode][]summaries.SummaryNode{}
	for a, aFlows := range c.Flows {
		as, err := flowNodeToSummaryNode(a)
		if err != nil {
			return summaries.DetailedSummary{}, err
		}
		for _, b := range aFlows {
			bs, err := flowNodeToSummaryNode(b)
			if err != nil {
				return summaries.DetailedSummary{}, err
			}
			if !slices.Contains(flows[as], bs) {
				flows[as] = append(flows[as], bs)
			}
		}
	}

	return summaries.DetailedSummary{
		Flows:   flows,
		Mutates: make([]summaries.SummaryNode, 0),
	}, nil
}

// ComputeClosedSummary computes the transitively closed summary for function f.
// This uses both the intra- and inter-procedural data flow analyses.
func ComputeClosedSummary(
	ctx context.Context,
	s *dataflow.State,
	f *ssa.Function,
) (ClosedInterproceduralSummary, error) {
	if len(s.FlowGraph.Summaries) == 0 {
		return ClosedInterproceduralSummary{}, fmt.Errorf("data flow state is not initialized")
	}
	s.FlowGraph.Sync()

	graph, ok := s.FlowGraph.Summaries[f]
	if !ok {
		return ClosedInterproceduralSummary{}, fmt.Errorf("failed to find summary for function %s", f)
	}
	if !graph.Constructed || graph.IsInterfaceContract || graph.IsPreSummarized {
		graph = dataflow.NewSummaryGraph(s, f, dataflow.GetUniqueFunctionID(), nil, nil)
		graph.IsInterfaceContract = false
		graph.IsPreSummarized = false
		graph.Constructed = false
		_, err := dataflow.RunIntraProcedural(ctx, s, graph)
		if err != nil {
			return ClosedInterproceduralSummary{},
				fmt.Errorf("failed to run intra-procedural data flow analysis: %v", err)
		}
	}

	// The reachable set bounds global write->read jumps in the visitor to the call tree actually
	// being explored for f's own summary.
	// It is computed once and reused across all inputs below, since it only depends on f.
	reachable := functionsReachableFrom(s.PointerAnalysis.CallGraph, f)

	flows := make(map[FlowNode][]FlowNode)
	unsoundness := &Unsoundness{}
	recordedUnsoundness := make(map[*ssa.Function]bool)
	for _, param := range graph.Params {
		for _, p := range leafPathsUpTo(param.Type(), maxPathLen) {
			v := newInputVisitor(p.String(), reachable, unsoundness, recordedUnsoundness)
			v.Visit(ctx, s, dataflow.NodeWithTrace{Node: param})
			// if there are no flows, don't add them
			if len(v.flows) == 0 {
				continue
			}
			from := FlowNode{Node: param, Path: p.String()}
			for _, target := range v.flows {
				to := FlowNode{Node: target.Node, Path: target.Path}
				if !slices.Contains(flows[from], to) {
					flows[from] = append(flows[from], to)
				}
			}
		}
	}
	if s.Report.HasErrors() {
		errs := s.Report.CheckError()
		return ClosedInterproceduralSummary{}, fmt.Errorf(
			"failed to run the inter-procedural data flow analysis: %w",
			errors.Join(errs...))
	}

	for fn, completeSummary := range s.FlowGraph.Summaries {
		if fn == f {
			return ClosedInterproceduralSummary{
				Graph:       completeSummary,
				Flows:       flows,
				Unsoundness: *unsoundness,
			}, nil
		}
	}

	panic("failed to find computed summary in graph")
}

// inputVisitor is a data flow Visitor that computes the data flows from an input to a function
// inter-procedurally.
// The entrypoint is an input (parameter) to the function.
// If you run the Visit method on every input to the function you want to summarize, then the
// summary of that function will be complete (sound).
//
// NOTE This does not track flows to boolean operators that short-circuit.
//
// inputVisitor implements the dataflow.Visitor interface.
type inputVisitor struct {
	flows      []flowTarget // flows is the data flows from function input to outputs
	entry      dataflow.NodeWithTrace
	visited    map[*dataflow.CallStack]bool
	seen       map[dataflow.KeyType]bool
	accessPath string // path is the access path of the node. It is empty if field-insensitive.
	// reachable is the set of functions transitively reachable (via the call graph) from the
	// function being summarized, including that function itself. It bounds global write->read
	// jumps to the call tree actually being explored: a function that is not in this set can never
	// have a call site inside the summarized function's own body, so it can never be part of a
	// path that loops back to one of the summarized function's own nodes. A nil map disables the
	// bound (used when the call graph isn't available).
	reachable map[*ssa.Function]bool
	// unsoundness stores the possible unsound features of analyzing the function and any of its
	// transitively reachable callees (via taint flow from an input).
	// This is per-function meaning that it is shared across all the input visitors.
	unsoundness *Unsoundness
	// recordedUnsoundness tracks which functions' (top-level or callee) unsoundness has already
	// been tracked.
	// This is per-function meaning that it is shared across all the input visitors.
	recordedUnsoundness map[*ssa.Function]bool
}

// flowTarget is a data flow destination: a graph node reached at a specific object access path
// (e.g. ".a" for field a of a struct-typed node). Path is empty if the node is reached in a
// field-insensitive way, either because its type has no sub-fields or the flow wasn't tracked
// field-sensitively.
type flowTarget struct {
	Node dataflow.GraphNode
	Path string
}

// newInputVisitor constructs a visitor to compute data flows from an input (always a parameter in
// this case) of the function with an access path if field-sensitivity is required.
//
// reachable is the set of functions transitively reachable from the function being summarized (see
// FunctionsReachableFrom); it may be nil, in which case global write->read jumps are unbounded.
func newInputVisitor(
	accessPath string, reachable map[*ssa.Function]bool,
	unsoundness *Unsoundness, recordedUnsoundness map[*ssa.Function]bool) *inputVisitor {

	return &inputVisitor{
		entry:               dataflow.NodeWithTrace{},
		visited:             make(map[*dataflow.CallStack]bool),
		seen:                make(map[dataflow.KeyType]bool),
		accessPath:          accessPath,
		reachable:           reachable,
		unsoundness:         unsoundness,
		recordedUnsoundness: recordedUnsoundness,
	}
}

// functionsReachableFrom returns the set of functions transitively reachable from root via the call
// graph cg (following callees), including root itself.
func functionsReachableFrom(cg *callgraph.Graph, root *ssa.Function) map[*ssa.Function]bool {
	reach := make(map[*ssa.Function]bool)
	if cg == nil {
		reach[root] = true
		return reach
	}
	rootNode := cg.Nodes[root]
	if rootNode == nil {
		reach[root] = true
		return reach
	}
	queue := []*callgraph.Node{rootNode}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if node == nil || node.Func == nil || reach[node.Func] {
			continue
		}
		reach[node.Func] = true
		for _, edge := range node.Out {
			queue = append(queue, edge.Callee)
		}
	}
	return reach
}

// Visit adds data flow information from entry to the inter-procedural data flow graph.
//
//gocyclo:ignore
func (v *inputVisitor) Visit(ctx context.Context, s *dataflow.State, entry dataflow.NodeWithTrace) {
	entryParam, ok := entry.Node.(*dataflow.ParamNode)
	if !ok {
		s.Report.AddError("", fmt.Errorf("entrypoint to FunctionVisitor is not a ParamNode: %v (%T)",
			entry.Node, entry.Node))
		return
	}

	v.entry = entry
	v.seen = make(map[dataflow.KeyType]bool)

	logger := s.Logger
	logger.Debugf("")
	logger.Debugf(" entrypoint: %s\n",
		formatutil.Blue(v.entry.Node.String()))
	logger.Debugf("   %s %s\n", formatutil.Green("Found at"), v.entry.Node.Position(s))

	logger.PushContext(formatutil.Faint(v.entry.Node.LongID()))
	defer logger.PopContext()

	entryNode := &dataflow.VisitorNode{
		NodeWithTrace: entry,
		AccessPaths:   []string{v.accessPath},
		Prev:          nil,
		Depth:         0,
		Status:        dataflow.VisitorNodeStatus{Kind: dataflow.DefaultTracing},
	}

	// Record sources of unsoundness in the function.
	v.recordUnsoundness(entry.Node.Graph().Parent)

	que := []*dataflow.VisitorNode{}
	// First initialize the analysis by visiting all outgoing edges of the parameter
	for nextNode, edgeInfos := range entry.Node.Out() {
		for _, edgeInfo := range edgeInfos {
			nextNodeWithTrace := dataflow.NodeWithTrace{
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

		switch graphNode := cur.Node.(type) {

		// This is a parameter node. We have reached this node either from a function call and the stack is non-empty,
		// or we reached this node from another flow inside the function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		//- if the stack is empty, there is no calling context. The flow goes back to every possible call site of
		// the function's parameter.
		case *dataflow.ParamNode:
			if cur.Prev != nil && cur.Prev.Node != nil {
				callArg, prevIsCallArg := cur.Prev.Node.(*dataflow.CallNodeArg)
				if cur.Prev.Node.Graph() != graphNode.Graph() || (prevIsCallArg &&
					callArg.ParentNode().Callee() == graphNode.Graph().Parent) {
					// Flows inside the function body. The data propagates to other locations inside the function body
					// Second part of the condition allows self-recursive calls to be used
					for nextNode, edgeInfos := range graphNode.Out() {
						for _, edgeInfo := range edgeInfos {
							nextNodeWithTrace := dataflow.NodeWithTrace{
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
			if callSite := dataflow.UnwindCallstackFromCallee(graphNode.Graph().Callsites, cur.Trace); callSite != nil {
				err := dataflow.CheckIndex(s, graphNode, callSite, "[Unwinding callstack] Argument at call site")
				if err != nil {
					s.Report.AddError("unwinding call stack at "+graphNode.Position(s).String(), err)
				} else {
					// Follow taint on matching argument at call site
					nextNodeArg := callSite.Args()[graphNode.Index()]
					if nextNodeArg != nil {
						nextNodeWithTrace := dataflow.NodeWithTrace{
							Node:         nextNodeArg,
							Trace:        cur.Trace.Parent(),
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, dataflow.EdgeInfo{})
					}
				}
			} else {
				// If the callstack is empty and the parameter is of the same function as the entrypoint,
				// then we stop analyzing further
				if graphNode.Graph().Parent == entryParam.Graph().Parent {
					s.Logger.Tracef("no callstack and parameter is entrypoint: dataflow from parameter is complete\n")
					v.addFlow(graphNode, cur.AccessPaths)
					continue
				}

				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					err := dataflow.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site")
					if err != nil {
						s.Report.AddError("argument at call site "+graphNode.String(), err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						if !callSiteArg.Graph().Constructed {
							v.onDemandIntraProcedural(ctx, s, callSiteArg.Graph())
						}
						for nextNode, edgeInfos := range callSiteArg.Out() {
							for _, edgeInfo := range edgeInfos {
								nextNodeWithTrace := dataflow.NodeWithTrace{
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
		case *dataflow.CallNodeArg:
			// Flow to next call
			callSite := graphNode.ParentNode()

			if goroutine, ok := callSite.CallSite().(*ssa.Go); ok {
				v.unsoundness.DataflowFeatures.GoUsages = append(
					v.unsoundness.DataflowFeatures.GoUsages, s.Program.Fset.Position(goroutine.Pos()))
			}

			// Record sources of unsoundness in the callee being entered (defers/recover usage).
			// This is what makes the naive method's unsoundness tracking cover the whole
			// transitively-explored call tree, not just the entry function.
			if callee := callSite.Callee(); callee != nil {
				v.recordUnsoundness(callee)
			}

			// Logic for when the summary has not been created
			if callSite.CalleeSummary == nil {
				if callSite.Callee() == nil {
					panic("callsite has no callee")
				}
				callSite.CalleeSummary = dataflow.NewSummaryGraph(s, callSite.Callee(), dataflow.GetUniqueFunctionID(), nil, nil)
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
				nextNodeWithTrace := dataflow.NodeWithTrace{
					Node:         nextNode,
					Trace:        newCallStack,
					ClosureTrace: cur.ClosureTrace,
				}
				que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, dataflow.EdgeInfo{})
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
						nextNodeWithTrace := dataflow.NodeWithTrace{
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
		case *dataflow.ReturnValNode:
			// If the return node is a return of the parameter's function, then stop analyzing further
			if graphNode.Graph().Parent == entryParam.SsaNode().Parent() {
				s.Logger.Tracef("dataflow to return is complete")
				v.addFlow(graphNode, cur.AccessPaths)
				continue
			}

			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if callSiteFromCallStack := dataflow.UnwindCallstackFromCallee(graphNode.Graph().Callsites, cur.Trace); callSiteFromCallStack != nil {
				logger.Tracef("unwound caller: %v\n", callSiteFromCallStack)
				if !callSiteFromCallStack.Graph().Constructed {
					v.onDemandIntraProcedural(ctx, s, callSiteFromCallStack.Graph())
				}
				for nextNode, edgeInfos := range callSiteFromCallStack.Out() {
					for _, edgeInfo := range edgeInfos {
						if !(graphNode.Index() >= 0 && edgeInfo.Index >= 0 && graphNode.Index() != edgeInfo.Index) {
							nextNodeWithTrace := dataflow.NodeWithTrace{
								Node:         nextNode,
								Trace:        cur.Trace.Parent(),
								ClosureTrace: cur.ClosureTrace,
							}
							que = v.addNext(s, que, cur, callSiteFromCallStack, nextNodeWithTrace, cur.Status, edgeInfo)
						}
					}
				}
			} else if cur.ClosureTrace != nil && dataflow.CheckClosureReturns(graphNode, cur.ClosureTrace.Label) {
				if !cur.ClosureTrace.Label.Graph().Constructed {
					v.onDemandIntraProcedural(ctx, s, cur.ClosureTrace.Label.Graph())
				}
				for nextNode, edgeInfos := range cur.ClosureTrace.Label.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := dataflow.NodeWithTrace{
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
							nextNodeWithTrace := dataflow.NodeWithTrace{
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
		case *dataflow.CallNode:
			if goroutine, ok := graphNode.CallSite().(*ssa.Go); ok {
				v.unsoundness.DataflowFeatures.GoUsages = append(
					v.unsoundness.DataflowFeatures.GoUsages, s.Program.Fset.Position(goroutine.Pos()))
			}

			if cur.Status.Kind == dataflow.ClosureTracing {
				if graphNode.CalleeSummary != nil &&
					// the following equality being true must imply that graphNode.CalleeSummary is a closure's summary
					graphNode.CalleeSummary == cur.Status.CurrentClosure() {
					fv := cur.Status.CurrentClosure().Parent.FreeVars[cur.Status.TracingInfo.Index]

					if fv != nil {
						nextNodeWithTrace := dataflow.NodeWithTrace{
							Node:         graphNode.CalleeSummary.FreeVars[fv],
							Trace:        cur.Trace.Add(graphNode),
							ClosureTrace: cur.ClosureTrace,
						}

						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status.PopClosure(), dataflow.EdgeInfo{})
					} else {
						s.Report.AddError(
							fmt.Sprintf("no free variable matching bound variable in %s",
								graphNode.CalleeSummary.Parent.String()),
							fmt.Errorf("at position %d", cur.Status.TracingInfo.Index))
					}
				}
			}
			// We pop the call from the stack and continue inside the caller
			var trace *dataflow.NodeTree[*dataflow.CallNode]
			if cur.Trace != nil {
				trace = cur.Trace.Parent()
			}
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
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
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         arg,
						Trace:        trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, dataflow.EdgeInfo{})
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
		case *dataflow.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the df edges between arguments
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
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
				closureNode.ClosureSummary = dataflow.NewSummaryGraph(s, closureNode.Graph().Parent, dataflow.GetUniqueFunctionID(), nil, nil)
			}
			if !closureNode.ClosureSummary.Constructed {
				v.onDemandIntraProcedural(ctx, s, closureNode.ClosureSummary)
				s.FlowGraph.Sync()
			}

			closureNodeWithTrace := dataflow.NodeWithTrace{
				Node:         closureNode,
				Trace:        dataflow.UnwindCallStackToFunc(cur.Trace, closureNode.Graph().Parent),
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}

			que = v.addNext(s, que, cur, nil, closureNodeWithTrace,
				dataflow.VisitorNodeStatus{
					Kind:        dataflow.ClosureTracing,
					TracingInfo: cur.Status.TracingInfo.Next(closureNode.ClosureSummary, graphNode.Index()),
				},
				dataflow.EdgeInfo{})

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		// The date can also flow from the function body to the free var node, in which case it implies the bound
		// variable (in the caller) is tainted after the function returns.
		case *dataflow.FreeVarNode:
			// Flows inside the function
			if cur.Prev == nil || (cur.Prev.Node.Graph() != graphNode.Graph()) {
				for nextNode, edgeInfos := range graphNode.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := dataflow.NodeWithTrace{
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
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         bv,
						Trace:        cur.Trace.Parent(),
						ClosureTrace: cur.ClosureTrace.Parent(),
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, dataflow.EdgeInfo{})
				} else {
					s.Report.AddError(
						fmt.Sprintf("no bound variable matching free variable in %s",
							cur.ClosureTrace.Label.ClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
					//panic(fmt.Errorf("no bound variable matching free variable in %s at position %d",
					//cur.ClosureTrace.Label.ClosureSummary.Parent.String(), graphNode.Index()))
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
						dataflow.BuildSummary(s, f)
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
						nextNodeWithTrace := dataflow.NodeWithTrace{
							Node:         bvs[graphNode.Index()],
							Trace:        cur.Trace,
							ClosureTrace: nil,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, dataflow.EdgeInfo{})
					} else {
						panicOnUnexpectedMissingFreeVar(s, makeClosureSite, graphNode)
					}
				}
			}

		// A closure node is usually reached when the visitor is tracing a specific closure
		case *dataflow.ClosureNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
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
		case *dataflow.SyntheticNode, *dataflow.BuiltinCallNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

		case *dataflow.AccessGlobalNode:
			if graphNode.IsWrite {
				// If taint flows to a global that is outside of the transitive callees of the
				// top-level function, then the summary is potentially unsound because the global
				// can induce new taint flows that are not captured by the summary.
				for nextNode := range graphNode.Global.ReadLocations {
					f := nextNode.Graph().Parent
					if v.reachable != nil && !v.reachable[f] {
						logger.Warnf(
							"flow to global %s outside of transitive callees of %v:"+
								" check is potentially unsound\n",
							nextNode, f)
						v.unsoundness.CheckFeatures.GlobalUsages = append(
							v.unsoundness.CheckFeatures.GlobalUsages, nextNode.Position(s))
						continue
					}
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         nextNode,
						Trace:        nil,
						ClosureTrace: nil,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace,
						dataflow.VisitorNodeStatus{Kind: dataflow.DefaultTracing},
						dataflow.EdgeInfo{})
				}
			} else {
				// From a read location, tainted data follows the node's outgoing edges within its
				// own function.
				for nextNode, edgeInfos := range graphNode.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := dataflow.NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			}

		// A BoundLabel flows to the body of the closure that captures it.
		case *dataflow.BoundLabelNode:
			destClosureSummary := graphNode.DestClosure()
			if destClosureSummary == nil {
				closureFn := graphNode.DestInfo().MakeClosure.Fn.(*ssa.Function)
				// The function that created the closure is not reachable, so it can't be the case
				// that the data would flow from that closure creation site.
				if !s.IsReachableFunction(closureFn) {
					break
				}
				destClosureSummary = dataflow.BuildSummary(s, closureFn)
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

			closureNodeWithTrace := dataflow.NodeWithTrace{
				Node:         closureNode,
				Trace:        dataflow.UnwindCallStackToFunc(cur.Trace, closureNode.Graph().Parent),
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}

			que = v.addNext(s, que, cur, nil, closureNodeWithTrace,
				dataflow.VisitorNodeStatus{
					Kind:        dataflow.ClosureTracing,
					TracingInfo: cur.Status.TracingInfo.Next(closureNode.ClosureSummary, graphNode.Index()),
				},
				dataflow.EdgeInfo{})

		case *dataflow.IfNode:
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
func (v *inputVisitor) onDemandIntraProcedural(ctx context.Context, s *dataflow.State, summary *dataflow.SummaryGraph) {
	s.Logger.Infof("[on-demand descent] summarizing callee: %s", summary.Parent)
	elapsed, err := dataflow.RunIntraProcedural(ctx, s, summary)
	s.Logger.Debugf("%-12s %-90s [%.2f s]\n", " ", summary.Parent.String(), elapsed.Seconds())
	if err != nil {
		panic(fmt.Sprintf("failed to run intra-procedural analysis : %v", err))
	}
}

// recordUnsoundness records unsound dataflow features of f.
// NOTE This does not include globals because we track those in the visitor.
func (v *inputVisitor) recordUnsoundness(f *ssa.Function) {
	if _, ok := v.recordedUnsoundness[f]; ok {
		return
	}

	deferRes := defers.AnalyzeFunction(f, config.NewLogger(config.ErrLevel))
	if !deferRes.DeferStackBounded {
		v.unsoundness.DataflowFeatures.HasUnboundedDefers = true
	}
	var recovers []token.Position
	lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
		if isRecoverInstr(instr) {
			pos := f.Prog.Fset.Position(instr.Pos())
			if !slices.Contains(recovers, pos) {
				recovers = append(recovers, pos)
			}
		}
	})
	v.unsoundness.DataflowFeatures.RecoverUsages = append(
		v.unsoundness.DataflowFeatures.RecoverUsages, recovers...)

	v.recordedUnsoundness[f] = true
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
func (v *inputVisitor) addNext(s *dataflow.State,
	que []*dataflow.VisitorNode,
	cur *dataflow.VisitorNode,
	intermediateNode dataflow.GraphNode,
	nextNodeWithTrace dataflow.NodeWithTrace,
	nextStatus dataflow.VisitorNodeStatus,
	edgeInfo dataflow.EdgeInfo) []*dataflow.VisitorNode {

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
		prevNode = &dataflow.VisitorNode{
			NodeWithTrace: dataflow.NodeWithTrace{
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
	nextVisitorNode := &dataflow.VisitorNode{
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

// addFlow adds a data flow from function input to function output, reached at the given access
// paths.
func (v *inputVisitor) addFlow(to dataflow.GraphNode, paths []string) {
	for _, p := range paths {
		v.flows = append(v.flows, flowTarget{Node: to, Path: p})
	}
}

// traceNodes prints trace information about the cur node.
func traceNode(s *dataflow.State, cur *dataflow.VisitorNode) {
	if !s.Logger.LogsTrace() {
		return
	}
	s.Logger.Tracef("(s=%v) Visiting %T node: %v\n\tat %v\n",
		cur.Status.Kind, cur.Node, cur.Node, cur.Node.Position(s))
	s.Logger.Tracef("Trace: %s\n", cur.Trace.String())
}

// panicOnUnexpectedMissingFreeVar **panics**, but adds and error to the state before.
func panicOnUnexpectedMissingFreeVar(s *dataflow.State, makeClosureSite *dataflow.ClosureNode, graphNode *dataflow.FreeVarNode) {
	s.Report.AddError(
		fmt.Sprintf("no bound variable matching free variable in %s",
			makeClosureSite.ClosureSummary.Parent.String()),
		fmt.Errorf("at position %d", graphNode.Index()))
	panic(
		fmt.Errorf(
			"[No Context] no bound variable matching free variable in %s at position %d",
			makeClosureSite.ClosureSummary.Parent.String(), graphNode.Index()))
}
