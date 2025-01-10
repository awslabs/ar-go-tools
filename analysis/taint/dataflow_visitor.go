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
	"go/token"
	"io"
	"slices"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// EscapeInfo contains information relative to the escape analysis
type EscapeInfo struct {
	InstructionLocality map[ssa.Instruction]*dataflow.EscapeRationale
	CallSiteInfo        map[ssa.CallInstruction]df.EscapeCallsiteInfo
}

func (e *EscapeInfo) String() string {
	s := "EscapeInfo:\n"
	for instr, local := range e.InstructionLocality {
		if val, isVal := instr.(ssa.Value); isVal {
			s += fmt.Sprintf(" [%v] %s\n", local, val)
		} else {
			s += fmt.Sprintf(" [%v] %s\n", local, instr)
		}

	}
	return s
}

// Visitor represents a taint flow Visitor that tracks taint flows from sources to sinks.
// It implements the [pkg/github.com/awslabs/ar-go-tools/Analysis/Dataflow.Visitor] interface.
type Visitor struct {
	taintSpec      *config.TaintSpec
	currentSource  df.NodeWithTrace
	roots          map[df.NodeWithTrace]*df.VisitorNode
	visited        map[*df.CallStack]bool
	escapeGraphs   map[*ssa.Function]map[df.KeyType]*EscapeInfo
	taints         *Flows
	coverageWriter io.StringWriter
	alarms         map[token.Pos]string
	seen           map[df.KeyType]bool
}

// NewVisitor returns a Visitor that can be used with
// [pkg/github.com/awslabs/ar-go-tools/analysis/dataflow.BuildAndRunVisitor] to run the taint analysis
// independently of the  [Analyze] function
func NewVisitor(ts *config.TaintSpec) *Visitor {
	return &Visitor{
		taintSpec:      ts,
		currentSource:  df.NodeWithTrace{},
		taints:         NewFlows(),
		coverageWriter: nil,
		roots:          map[df.NodeWithTrace]*df.VisitorNode{},
		visited:        map[*df.CallStack]bool{},
		escapeGraphs:   map[*ssa.Function]map[df.KeyType]*EscapeInfo{},
		alarms:         map[token.Pos]string{},
		seen:           make(map[df.KeyType]bool),
	}
}

// Reset resets the visitor by clearing the set of seen nodes
func (v *Visitor) Reset() {
	v.seen = make(map[df.KeyType]bool)
}

// CondError represents an error where taint flows to a conditional statement.
type CondError struct {
	Cond       *ssa.If        // Cond is the conditional statement
	ParentName string         // ParentName is the name of the function in which the conditional statement occurs
	Trace      string         // Trace is a string representing the taint trace
	Pos        token.Position // Pos is the position
}

func (e *CondError) Error() string {
	return fmt.Sprintf("taint flows to conditional statement %v in function %v: %v\n\tat %v", e.Cond, e.ParentName, e.Trace, e.Pos)
}

// Visit runs an inter-procedural analysis to add any detected taint flow from currentSource to a sink. This implements
// the visitor interface of the dataflow package.
//
//gocyclo:ignore
func (v *Visitor) Visit(s *df.State, source df.NodeWithTrace) {
	coverage := make(map[string]bool)
	v.Reset()
	goroutines := make(map[*ssa.Go]bool)
	v.currentSource = source
	logger := s.Logger
	logger.Infof("\n%s NEW SOURCE %s", strings.Repeat("*", 30), strings.Repeat("*", 30))
	logger.Infof("==> Source: %s\n", formatutil.Purple(v.currentSource.Node.String()))
	logger.Infof("%s %s\n", formatutil.Green("Found at"), v.currentSource.Node.Position(s))
	logger.Infof("  - Context: %s", dataflow.FuncNames(v.currentSource.Trace, s.Logger.LogsDebug()))

	v.roots[source] = &df.VisitorNode{
		NodeWithTrace: source,
		AccessPaths:   []string{""},
		Prev:          nil,
		Depth:         0,
		Status:        df.VisitorNodeStatus{Kind: df.DefaultTracing},
	}

	que := []*df.VisitorNode{v.roots[source]}

	if s.Config.UseEscapeAnalysis {
		v.initEscapeAnalysisInfo(s, source)
	}

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		cur := que[0]
		que = que[1:]
		// Report coverage information for the current node
		addCoverage(s, cur, coverage)

		traceNode(s, cur)

		// If the node is filtered out, we don't inspect children.
		// Test this before checking for sink in case this is a filtered argument in a sink call (this is common when
		// you are tracking flows to logging but don't care about integers and booleans for example).
		if dataflow.IsFiltered(s, v.taintSpec, cur.Node) {
			if _, isIf := cur.Node.(*df.IfNode); !isIf || v.taintSpec.FailOnImplicitFlow {
				// Filtered values logged at debug level -- there can be many of those.
				logger.Debugf("Filtered value: %s\n", cur.Node.String())
				logger.Debugf("At: %s\n", cur.Node.Position(s))
			}
			continue
		}

		// If node is sink, then we reached a sink from a source, and we must log the taint flow.
		if dataflow.IsSink(s, v.taintSpec, cur.Node) && cur.Status.Kind == df.DefaultTracing {
			// Don't report taint flow if the sink location is annotated with //argot:ignore
			if s.Annotations.IsIgnoredPos(cur.Node.Position(s), v.taintSpec.Tag) {
				s.Logger.Infof("//argot:ignore taint flow to %s",
					cur.Node.Position(s))
			} else {
				if v.taints.addNewPathCandidate(NewFlowNode(v.currentSource), NewFlowNode(cur.NodeWithTrace)) {
					logTaintFlow(s, v.currentSource, cur)
					s.Report.AddEntry(s.State, config.ReportDesc{
						Tool:     config.TaintTool,
						Tag:      v.taintSpec.Tag,
						Severity: v.taintSpec.Severity,
						Content:  newFlowReport(s, v.currentSource, cur, v.taintSpec),
					})
					if v.taintSpec.Severity == config.Critical {
						panic(fmt.Sprintf("taint flows to critical location (problem tag %s)", v.taintSpec.Tag))
					}
				}
				// Stop if there is a limit on number of alarms, and it has been reached.
				if !s.IncrementAndTestAlarms() {
					logger.Warnf("Reached the limit of %d alarms.", s.Config.MaxAlarms)
					return
				}
			}
			// A sink does not have successors in the taint flow analysis (but other sinks can be reached
			// as there are still values flowing).
			continue
		}

		// If node is sanitizer, we don't want to propagate further
		// The validators will be checked in the addNext function
		if dataflow.IsSanitizer(s, v.taintSpec, cur.Node) {
			logger.Infof("Sanitizer encountered: %s\n", cur.Node.String())
			logger.Infof("At: %s\n", cur.Node.Position(s))
			continue
		}

		// Check that the node does not correspond to a non-constructed summary
		if !cur.Node.Graph().Constructed {
			// If on-demand summarization is enabled, build the summary and set the node's summary to point to the
			// built summary
			v.onDemandIntraProcedural(s, cur.Node.Graph())
		}

		switch graphNode := cur.Node.(type) {

		// This is a parameter node. We have reached this node either from a function call and the stack is non-empty,
		// or we reached this node from another flow inside the function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		//- if the stack is empty, there is no calling context. The flow goes back to every possible call site of
		// the function's parameter.
		case *df.ParamNode:
			if cur.Prev != nil && cur.Prev.Node != nil {
				callArg, prevIsCallArg := cur.Prev.Node.(*df.CallNodeArg)
				if cur.Prev.Node.Graph() != graphNode.Graph() || (prevIsCallArg &&
					callArg.ParentNode().Callee() == graphNode.Graph().Parent) {
					// Flows inside the function body. The data propagates to other locations inside the function body
					// Second part of the condition allows self-recursive calls to be used
					for nextNode, edgeInfos := range graphNode.Out() {
						for _, edgeInfo := range edgeInfos {
							nextNodeWithTrace := df.NodeWithTrace{
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
			if callSite := df.UnwindCallstackFromCallee(graphNode.Graph().Callsites, cur.Trace); callSite != nil {
				err := df.CheckIndex(s, graphNode, callSite, "[Unwinding callstack] Argument at call site")
				if err != nil {
					s.Report.AddError("unwinding call stack at "+graphNode.Position(s).String(), err)
				} else {
					// Follow taint on matching argument at call site
					nextNodeArg := callSite.Args()[graphNode.Index()]
					if nextNodeArg != nil {
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         nextNodeArg,
							Trace:        cur.Trace.Parent,
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
					}
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					err := df.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site")
					if err != nil {
						s.Report.AddError("argument at call site "+graphNode.String(), err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						if !callSiteArg.Graph().Constructed {
							v.onDemandIntraProcedural(s, callSiteArg.Graph())
						}
						for nextNode, edgeInfos := range callSiteArg.Out() {
							for _, edgeInfo := range edgeInfos {
								nextNodeWithTrace := df.NodeWithTrace{
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
		case *df.CallNodeArg:
			// Flow to next call
			callSite := graphNode.ParentNode()

			df.CheckNoGoRoutine(s, goroutines, callSite)

			// Logic for when the summary has not been created
			if callSite.CalleeSummary == nil {
				if callSite.Callee() == nil {
					panic("callsite has no callee")
				}
				// the callee summary may not have been created yet
				if s.IsReachableFunction(callSite.Callee()) {
					panic(fmt.Sprintf("unexpected missing callee summary for reachable function %s",
						callSite.Callee()))
				} else {
					// Ignore the callee, it is not reachable.
					// If it was reachable, there should be a summary. If a bug is encountered here, then the
					// problem should be in the initial reachability computation logic, not here.
					break
				}
			}
			// callSiteFromCallStack.CalleeSummary should be non-nil from now on in this branch.

			// Logic for when the summary has not been constructed
			if !callSite.CalleeSummary.Constructed {
				v.onDemandIntraProcedural(s, callSite.CalleeSummary)
			}

			// Computing context-sensitive information for the analyses

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				// This is where a function gets "called" and the next nodes will be analyzed in a different context
				nextNode := callSite.CalleeSummary.Params[param]

				newCallStack := cur.Trace.Add(callSite)
				v.visited[newCallStack] = true
				nextNodeWithTrace := df.NodeWithTrace{
					Node:         nextNode,
					Trace:        newCallStack,
					ClosureTrace: cur.ClosureTrace,
				}
				que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
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
						nextNodeWithTrace := df.NodeWithTrace{
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
		case *df.ReturnValNode:
			// Check call stack is empty, and caller is one of the callsites
			// Caller can be different if value flowed in function through a closure definition
			if callSiteFromCallStack := df.UnwindCallstackFromCallee(graphNode.Graph().Callsites, cur.Trace); callSiteFromCallStack != nil {
				logger.Tracef("unwound caller: %v\n", callSiteFromCallStack)
				if !callSiteFromCallStack.Graph().Constructed {
					v.onDemandIntraProcedural(s, callSiteFromCallStack.Graph())
				}
				for nextNode, edgeInfos := range callSiteFromCallStack.Out() {
					for _, edgeInfo := range edgeInfos {
						if !(graphNode.Index() >= 0 && edgeInfo.Index >= 0 && graphNode.Index() != edgeInfo.Index) {
							nextNodeWithTrace := df.NodeWithTrace{
								Node:         nextNode,
								Trace:        cur.Trace.Parent,
								ClosureTrace: cur.ClosureTrace,
							}
							que = v.addNext(s, que, cur, callSiteFromCallStack, nextNodeWithTrace, cur.Status, edgeInfo)
						}
					}
				}
			} else if cur.ClosureTrace != nil && df.CheckClosureReturns(graphNode, cur.ClosureTrace.Label) {
				if !cur.ClosureTrace.Label.Graph().Constructed {
					v.onDemandIntraProcedural(s, cur.ClosureTrace.Label.Graph())
				}
				for nextNode, edgeInfos := range cur.ClosureTrace.Label.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace.Parent,
						}
						que = v.addNext(s, que, cur, cur.ClosureTrace.Label, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					if !callSite.Graph().Constructed {
						v.onDemandIntraProcedural(s, callSite.Graph())
					}
					for nextNode, edgeInfos := range callSite.Out() {
						for _, edgeInfo := range edgeInfos {
							nextNodeWithTrace := df.NodeWithTrace{
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
		case *df.CallNode:
			df.CheckNoGoRoutine(s, goroutines, graphNode)

			if cur.Status.Kind == df.ClosureTracing {
				if graphNode.CalleeSummary != nil &&
					// the following equality being true must imply that graphNode.CalleeSummary is a closure's summary
					graphNode.CalleeSummary == cur.Status.CurrentClosure() {
					fv := cur.Status.CurrentClosure().Parent.FreeVars[cur.Status.TracingInfo.Index]

					if fv != nil {
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         graphNode.CalleeSummary.FreeVars[fv],
							Trace:        cur.Trace.Add(graphNode),
							ClosureTrace: cur.ClosureTrace,
						}

						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status.PopClosure(), df.EdgeInfo{})
					} else {
						s.Report.AddError(
							fmt.Sprintf("no free variable matching bound variable in %s",
								graphNode.CalleeSummary.Parent.String()),
							fmt.Errorf("at position %d", cur.Status.TracingInfo.Index))
					}
				}
			}
			// We pop the call from the stack and continue inside the caller
			var trace *df.NodeTree[*df.CallNode]
			if cur.Trace != nil {
				trace = cur.Trace.Parent
			}
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

			// If the call is a source node, the actual source node may be one of its arguments
			// See the closures_paper test for an example
			if graphNode == source.Node {
				for _, arg := range graphNode.Args() {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         arg,
						Trace:        trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
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
		case *df.BoundVarNode:
			// Flows inside the function creating the closure (where MakeClosure happens)
			// This is similar to the df edges between arguments
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

			closureNode := graphNode.ParentNode()

			if !closureNode.ClosureSummary.Constructed {
				v.onDemandIntraProcedural(s, closureNode.ClosureSummary)
				s.FlowGraph.Sync()
			}

			closureNodeWithTrace := df.NodeWithTrace{
				Node:         closureNode,
				Trace:        df.UnwindCallStackToFunc(cur.Trace, closureNode.Graph().Parent),
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}

			que = v.addNext(s, que, cur, nil, closureNodeWithTrace,
				df.VisitorNodeStatus{
					Kind:        df.ClosureTracing,
					TracingInfo: cur.Status.TracingInfo.Next(closureNode.ClosureSummary, graphNode.Index()),
				},
				df.EdgeInfo{})

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		// The date can also flow from the function body to the free var node, in which case it implies the bound
		// variable (in the caller) is tainted after the function returns.
		case *df.FreeVarNode:
			// Flows inside the function
			if cur.Prev == nil || (cur.Prev.Node.Graph() != graphNode.Graph()) {
				for nextNode, edgeInfos := range graphNode.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := df.NodeWithTrace{
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
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         bv,
						Trace:        cur.Trace.Parent,
						ClosureTrace: cur.ClosureTrace.Parent,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
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
					if f != nil {
						df.BuildSummary(s, f)
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
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         bvs[graphNode.Index()],
							Trace:        cur.Trace,
							ClosureTrace: nil,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
					} else {
						panicOnUnexpectedMissingFreeVar(s, makeClosureSite, graphNode)
					}
				}
			}

		// A closure node is usually reached when the visitor is tracing a specific closure
		case *df.ClosureNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := df.NodeWithTrace{
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
		case *df.SyntheticNode, *df.BuiltinCallNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

		case *df.AccessGlobalNode:
			if graphNode.IsWrite {
				for f := range s.ReachableFunctions() {
					if lang.FnReadsFrom(f, graphNode.Global.Value()) {
						logger.Tracef("Global %v read in function: %v\n", graphNode, f)
						df.BuildSummary(s, f)
					}
				}

				// Tainted data is written to ALL locations where the global is read.
				for nextNode := range graphNode.Global.ReadLocations {
					// Global jump makes trace irrelevant if we don't follow the call graph!
					nextNodeWithTrace := df.NodeWithTrace{
						Node:         nextNode,
						Trace:        nil,
						ClosureTrace: cur.ClosureTrace,
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
				}
			} else {
				// From a read location, tainted data follows the out edges of the node
				for nextNode, edgeInfos := range graphNode.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			}

		// A BoundLabel flows to the body of the closure that captures it.
		case *df.BoundLabelNode:
			if v.taintSpec.SkipBoundLabels {
				break
			}
			destClosureSummary := graphNode.DestClosure()
			if destClosureSummary == nil {
				destClosureSummary = df.BuildSummary(s, graphNode.DestInfo().MakeClosure.Fn.(*ssa.Function))
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

			closureNodeWithTrace := df.NodeWithTrace{
				Node:         closureNode,
				Trace:        df.UnwindCallStackToFunc(cur.Trace, closureNode.Graph().Parent),
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}

			que = v.addNext(s, que, cur, nil, closureNodeWithTrace,
				df.VisitorNodeStatus{
					Kind:        df.ClosureTracing,
					TracingInfo: cur.Status.TracingInfo.Next(closureNode.ClosureSummary, graphNode.Index()),
				},
				df.EdgeInfo{})
		case *df.IfNode:
			// If only explicit taint flows should be tracked,
			// then don't track flow inside of conditionals (information flow)
			if !v.taintSpec.FailOnImplicitFlow {
				break
			}

			// taint is expected to flow to validators
			if dataflow.IsValidatorCondition(v.taintSpec, graphNode.SsaNode().Cond, true) {
				break
			}

			cond := graphNode.SsaNode()
			pos := graphNode.Position(s)

			// if the node is ignored, don't record an error
			if s.Annotations.IsIgnoredPos(pos, v.taintSpec.Tag) {
				s.Logger.Infof("//argot:ignore implicit flow to conditional statement at %s", pos)
				break
			}

			err := &CondError{Cond: cond, ParentName: cur.Node.ParentName(), Trace: cur.Trace.SummaryString(), Pos: pos}
			logger.Warnf("%v\n", err)
			s.Report.AddError("cond", err)
		}
	}

	if v.coverageWriter != nil {
		reportCoverage(coverage, v.coverageWriter)
	}
}

// initEscapeAnalysisInfo initializes the information required by the escape analysis.
// This consists mainly in storing the escape graph of the function where the source appears
func (v *Visitor) initEscapeAnalysisInfo(s *df.State, source df.NodeWithTrace) {
	sourceCaller := source.Node.Graph().Parent
	var rootKey df.KeyType
	// Resolve the context
	if source.Trace != nil {
		rootKey = source.Trace.Parent.Key()
	} else {
		rootKey = ""
	}
	v.storeEscapeGraphInContext(s, sourceCaller, rootKey,
		s.EscapeAnalysisState.ComputeArbitraryContext(sourceCaller))

	escapeGraph := v.escapeGraphs[sourceCaller][rootKey]
	v.checkEscape(s, source.Node, escapeGraph)

	callNode, isCallNode := source.Node.(*df.CallNode)
	if isCallNode {
		v.storeEscapeGraph(s, source.Trace, callNode)
	}
}

// onDemandIntraProcedural runs the intra-procedural on the summary, modifying its state
// This panics when the analysis fails, because it is expected that an error will cause any further result
// to be invalid.
func (v *Visitor) onDemandIntraProcedural(s *df.State, summary *df.SummaryGraph) {
	s.Logger.Debugf("[On-demand] Summarizing %s...", summary.Parent)
	elapsed, err := df.RunIntraProcedural(s, summary)
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
func (v *Visitor) addNext(s *df.State,
	que []*df.VisitorNode,
	cur *df.VisitorNode,
	intermediateNode df.GraphNode,
	nextNodeWithTrace df.NodeWithTrace,
	nextStatus df.VisitorNodeStatus,
	edgeInfo df.EdgeInfo) []*df.VisitorNode {

	// Check for validators
	if edgeInfo.Cond != nil && len(edgeInfo.Cond.Conditions) > 0 {
		for _, condition := range edgeInfo.Cond.Conditions {
			if dataflow.IsValidatorCondition(v.taintSpec, condition.Value, condition.IsPositive) {
				s.Logger.Debugf("Validated %s.\n", condition)
				return que
			}
		}
	}
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
		prevNode = &df.VisitorNode{
			NodeWithTrace: df.NodeWithTrace{
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
	nextVisitorNode := &df.VisitorNode{
		NodeWithTrace: nextNodeWithTrace,
		AccessPaths:   nextNodeAccessPaths,
		Status:        nextStatus,
		Prev:          prevNode,
		Depth:         cur.Depth + 1,
	}

	// First set of stop conditions: node has already been seen, or depth exceeds limit
	if v.seen[nextVisitorNode.Key()] || s.Config.ExceedsMaxDepth(cur.Depth) {
		return que
	}

	// If configured, use the escape analysis to scan whether data on the edge escapes
	// This controls also how recursive calls are handled.
	escapeContextUpdated := false

	if s.Config.UseEscapeAnalysis {
		escapeContextUpdated = v.manageEscapeContexts(s, cur, nextNodeWithTrace.Node, nextNodeWithTrace.Trace)
	}

	// Second set of stopping conditions: the escape context is unchanged on a loop path
	if (nextNodeWithTrace.Trace.GetLassoHandle() != nil || nextNodeWithTrace.ClosureTrace.GetLassoHandle() != nil) &&
		!escapeContextUpdated {
		return que
	}

	cur.AddChild(nextVisitorNode)
	que = append(que, nextVisitorNode)
	v.seen[nextVisitorNode.Key()] = true
	return que
}

// fallbackEscapeContext computes an escape context for function f based on its
// callers. This is relatively expensive, so we only do it for places where the
// existing technique fails.
//
//gocyclo:ignore
func fallbackEscapeContext(f *ssa.Function, s *df.State) df.EscapeCallContext {
	cg := s.PointerAnalysis.CallGraph
	node := cg.Nodes[f]

	// State to compute upward reachability from f
	reachable := make(map[*callgraph.Node]bool, len(cg.Nodes))
	frontier := []*callgraph.Node{node}
	reachable[node] = true

	// State to converge the escape context state
	worklist := []*callgraph.Node{node}
	contexts := map[*callgraph.Node]dataflow.EscapeCallContext{}

	for len(frontier) != 0 {
		node := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if len(node.In) == 0 || node.Func.String() == "command-line-arguments.main" {
			// no in-edges are roots
			if _, ok := contexts[node]; !ok {
				contexts[node] = s.EscapeAnalysisState.ComputeArbitraryContext(node.Func)
			} else {
				contexts[node].Merge(s.EscapeAnalysisState.ComputeArbitraryContext(node.Func))
			}
		}
		for _, edge := range node.In {
			if _, ok := edge.Site.(*ssa.Go); ok {
				// go calls are roots
				if _, ok := contexts[node]; !ok {
					contexts[node] = s.EscapeAnalysisState.ComputeArbitraryContext(node.Func)
				} else {
					contexts[node].Merge(s.EscapeAnalysisState.ComputeArbitraryContext(node.Func))
				}
				continue
			}
			if !reachable[edge.Caller] {
				reachable[edge.Caller] = true
				frontier = append(frontier, edge.Caller)
				worklist = append(worklist, edge.Caller)
			}
		}
	}
	// Reachable now has the functions we need to compute the correct context.
	slices.Reverse(worklist) // we want to go top-down if possible
	s.Logger.Debugf("Worklist is\n")
	for _, n := range worklist {
		s.Logger.Debugf(" - %v\n", n.Func)
	}
	changed := false
	for {
		changed = false
		for _, node := range worklist {
			if ctx, ok := contexts[node]; !ok {
				// There is no context for the current function; wait until a future iteration where we have one
				changed = true
				s.Logger.Debugf("No context for %v, spinning loop\n", node.Func)
			} else {
				// Compute the contexts for the callsites in node.Func
				_, callsites := s.EscapeAnalysisState.ComputeInstructionLocalityAndCallsites(node.Func, ctx)
				// Propogate the context information to callees
				for _, edge := range node.Out {
					// Match up callgraph edges with escape information using the callsite instruction
					if callsiteInfo, ok := callsites[edge.Site]; ok {
						// Only propogate for callgraph nodes we care about
						if reachable[edge.Callee] {
							newIncomingContext := callsiteInfo.Resolve(edge.Callee.Func)
							// Check for an existing context, and update or add a new one
							if existingContext, ok := contexts[edge.Callee]; ok {
								thisChanged, newContext := existingContext.Merge(newIncomingContext)
								changed = thisChanged || changed
								contexts[edge.Callee] = newContext
							} else {
								changed = true
								contexts[edge.Callee] = newIncomingContext
							}
						}
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	return contexts[node]
}

func (v *Visitor) manageEscapeContexts(s *df.State, cur *df.VisitorNode, nextNode df.GraphNode,
	nextTrace *df.CallStack) bool {
	update := false

	// Update the contexts when a new function is called.
	switch curNode := cur.Node.(type) {
	case *df.CallNodeArg:
		callSite := curNode.ParentNode()
		update = v.storeEscapeGraph(s, nextTrace, callSite)
	case *df.CallNode:
		update = v.storeEscapeGraph(s, nextTrace, curNode)
	case *df.BoundLabelNode, *df.BoundVarNode:
		if nextTrace != nil {
			update = v.storeEscapeGraph(s, nextTrace, nextTrace.Label)
		} else {
			update = v.storeEscapeGraph(s, nil, nil) // this does nothing
		}
	}

	f := nextNode.Graph().Parent
	nKey := nextTrace.Key()
	if handle := nextTrace.GetLassoHandle(); handle != nil {
		// TODO: handle merging contexts for recursive functions
		// the "handle" of the lasso is the part of the context that will be common between all the recursive calls
		// of a given function. Recomputing escape contexts under each new complete callstack should converge.
		nKey = handle.Key()
	}
	escapeGraph := v.escapeGraphs[f][nKey]
	if escapeGraph != nil {
		v.checkEscape(s, nextNode, escapeGraph)
	} else if s.EscapeAnalysisState.IsSummarized(f) {
		s.Logger.Debugf("Using fallback context for function %s, precision may be lower",
			formatutil.Sanitize(f.String()))
		escapeNoContext := fallbackEscapeContext(f, s)
		i, c := s.EscapeAnalysisState.ComputeInstructionLocalityAndCallsites(f, escapeNoContext)
		escapeInfo := &EscapeInfo{i, c}
		v.checkEscape(s, nextNode, escapeInfo)
	} else {
		// The function doesn't have an escape graph explicitly, but we got here because of taint.
		// Thus, we might be missing taint escape. Ideally, this should be fixed by adjusting the allowlist.
		s.Logger.Warnf("Function %s has no escape information, but does have taint flow",
			formatutil.Sanitize(f.String()))
	}
	return update
}

// checkEscape checks that the instructions associated to the node do not involve operations that manipulate data
// that has escape, in the state s and under the escape context escapeInfo.
func (v *Visitor) checkEscape(s *df.State, node df.GraphNode, escapeInfo *EscapeInfo) {
	if escapeInfo == nil { // the escapeInfo must not be nil. A missing escapeInfo means an error in the algorithm.
		s.Report.AddError("missing escape graph",
			fmt.Errorf("was missing escape graph for node %s when checking escape", node))
		return
	}
	for instr := range node.Marks() {
		_, isCall := instr.(ssa.CallInstruction)
		rationale, isTracked := escapeInfo.InstructionLocality[instr]
		if !isCall && rationale != nil && isTracked {
			v.taints.addNewEscape(v.currentSource, instr, *rationale)
			v.raiseAlarm(s, instr.Pos(),
				fmt.Sprintf("instruction in %s is not local because %s!\n\tPosition: %s",
					node.Graph().Parent, rationale.String(), s.Program.Fset.Position(instr.Pos())))
		}
	}
}

// storeEscapeGraph computes the escape graph of callee in the context where it is called with stack. stack.Label should
// be the caller of callee
func (v *Visitor) storeEscapeGraph(s *df.State, stack *df.CallStack, callNode *df.CallNode) bool {
	if callNode == nil {
		return false
	}
	callee := callNode.Callee()
	if !s.EscapeAnalysisState.IsSummarized(callee) {
		return false
	}
	var escapeContext *EscapeInfo

	key := "" // key corresponding to no context if the function is a root
	if stack != nil {
		if stack.Parent != nil {
			key = stack.Parent.Key()
		}
		escapeContext = v.escapeGraphs[callNode.Graph().Parent][key]
	}

	// if trace is a lasso, stack is the context_key
	nextNodeContextKey := stack.GetLassoHandle().Key()
	if nextNodeContextKey == "" {
		nextNodeContextKey = stack.Key()
	}

	if escapeContext != nil {
		ctxt := escapeContext.CallSiteInfo[callNode.CallSite().Value()]
		if ctxt != nil {
			escapeCallContext := ctxt.Resolve(callee)
			v.storeEscapeGraphInContext(s, callee, nextNodeContextKey, escapeCallContext)
			return true
		}
	}

	s.Logger.Debugf("Storing fallback context for function %s, precision may be lower",
		formatutil.Sanitize(callee.String()))
	escapeNoContext := fallbackEscapeContext(callee, s)
	// escapeNoContext := s.EscapeAnalysisState.ComputeArbitraryContext(callee)
	v.storeEscapeGraphInContext(s, callee, nextNodeContextKey, escapeNoContext)
	return true
}

func (v *Visitor) storeEscapeGraphInContext(s *df.State, f *ssa.Function, key df.KeyType,
	ctx df.EscapeCallContext) {
	if v.escapeGraphs[f] == nil {
		v.escapeGraphs[f] = map[df.KeyType]*EscapeInfo{}
	}

	locality, info := s.EscapeAnalysisState.ComputeInstructionLocalityAndCallsites(f, ctx)
	v.escapeGraphs[f][key] = &EscapeInfo{locality, info}
}

// raiseAlarm raises an alarm (logs a warning message) if that alarm has not already been raised. This avoids repeated
// warning messages to the user.
func (v *Visitor) raiseAlarm(s *df.State, pos token.Pos, msg string) {
	if _, alreadyRaised := v.alarms[pos]; !alreadyRaised {
		s.Logger.Warnf(msg)
		v.alarms[pos] = msg
	}
}
