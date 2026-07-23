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
	"context"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/awslabs/ar-go-tools/analysis/config"
	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// EscapeInfo contains information relative to the escape analysis
type EscapeInfo struct {
	InstructionLocality map[ssa.Instruction]*df.EscapeRationale
	CallSiteInfo        map[*ssa.Call]df.EscapeCallsiteInfo
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
	interesting    InterestingFunctions
	// interfaceTypesSeen tracks, per callee function and interface method name, the widest
	// interface type recorded so far in InterestingFunctionSignals.InterfaceFanouts (see
	// recordInterfaceFanout): this lets later calls compare against the real *types.Interface to
	// detect subsumption (e.g. io.ReadCloser.Close is subsumed by io.Closer.Close) without
	// storing analysis-internal type information on the serializable InterfaceFanout struct.
	interfaceTypesSeen map[*ssa.Function]map[string]*types.Interface
}

// SetInterestingFunctions sets the InterestingFunctions map that this Visitor records signals
// into as it visits functions during taint propagation. Passing nil (the default) disables
// recording.
func (v *Visitor) SetInterestingFunctions(m InterestingFunctions) {
	v.interesting = m
}

// InterestingFunctions returns the signals recorded so far by this Visitor, or nil if recording
// is disabled (see SetInterestingFunctions).
func (v *Visitor) InterestingFunctions() InterestingFunctions {
	return v.interesting
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
func (v *Visitor) Visit(ctx context.Context, s *df.State, source df.NodeWithTrace) error {
	coverage := make(map[string]bool)
	v.Reset()
	goroutines := make(map[*ssa.Go]bool)
	v.currentSource = source
	logger := s.Logger
	logger.Debugf("")
	logger.Debugf(" entrypoint: %s\n",
		formatutil.Blue(v.currentSource.Node.String()))
	logger.Debugf("   %s %s\n", formatutil.Green("Found at"), v.currentSource.Node.Position(s))
	logger.Debugf("   Context: %s", df.FuncNames(v.currentSource.Trace, s.Logger.LogsDebug()))

	logger.PushContext(formatutil.Faint(v.currentSource.Node.LongID()))
	defer logger.PopContext()

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
		if df.IsFiltered(s, v.taintSpec, cur.Node) {
			if _, isIf := cur.Node.(*df.IfNode); !isIf || v.taintSpec.FailOnImplicitFlow {
				// Filtered values logged at debug level -- there can be many of those.
				logger.Debugf("Filtered value: %s\n", cur.Node.String())
				logger.Debugf("At: %s\n", cur.Node.Position(s))
			}
			continue
		}

		// If node is sink, then we reached a sink from a source, and we must log the taint flow.
		if _, sin := df.IsSink(s, v.taintSpec, cur.Node); sin && cur.Status.Kind == df.DefaultTracing {
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
					return nil
				}
			}
			// A sink does not have successors in the taint flow analysis (but other sinks can be reached
			// as there are still values flowing).
			continue
		}

		// If node is sanitizer, we don't want to propagate further
		// The validators will be checked in the addNext function
		if _, san := df.IsSanitizer(s, v.taintSpec, cur.Node); san {
			logger.Infof("Sanitizer encountered: %s\n", cur.Node.String())
			logger.Infof("At: %s\n", cur.Node.Position(s))
			continue
		}

		// Check that the node does not correspond to a non-constructed summary
		if !cur.Node.Graph().Constructed {
			// If on-demand summarization is enabled, build the summary and set the node's summary to point to the
			// built summary
			if err := v.onDemandIntraProcedural(ctx, s, cur.Node.Graph()); err != nil {
				return err
			}
		} else if cur.Node.Graph().IsPreSummarized {
			v.recordSummarizedReachable(s, cur.Node.Graph().Parent, cur.Node.Position(s))
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
							Trace:        cur.Trace.Parent(),
							ClosureTrace: cur.ClosureTrace,
						}
						que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
					}
				}
			} else {
				// NOTE: potential state space explosion
				// The value must always flow back to all call sites: we got here without context
				v.recordContextLossFanout(graphNode.Graph(), ContextLossCallSites, len(graphNode.Graph().Callsites))
				for _, callSite := range graphNode.Graph().Callsites {
					err := df.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site")
					if err != nil {
						s.Report.AddError("argument at call site "+graphNode.String(), err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						v.recordInterfaceFanout(s, callSite)
						if !callSiteArg.Graph().Constructed {
							if err := v.onDemandIntraProcedural(ctx, s, callSiteArg.Graph()); err != nil {
								return err
							}
						} else if callSiteArg.Graph().IsPreSummarized {
							v.recordSummarizedReachable(s, callSiteArg.Graph().Parent, callSiteArg.Position(s))
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

			if df.SpawnsGoroutine(s, goroutines, callSite) {
				v.recordUnsoundness(callSite.Graph(), UnsoundnessConcurrency)
			}
			v.recordInterfaceFanout(s, callSite)

			// Logic for when the summary has not been created
			if callSite.CalleeSummary == nil {
				if callSite.Callee() == nil {
					panic("callsite has no callee")
				}
				// the callee summary may not have been created yet, but if it's reachable then we should panic
				// because we cannot handle this case soundly.
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

			if !callSite.CalleeSummary.Constructed {
				if err := v.onDemandIntraProcedural(ctx, s, callSite.CalleeSummary); err != nil {
					return err
				}
			} else if callSite.CalleeSummary.IsPreSummarized {
				v.recordSummarizedReachable(s, callSite.CalleeSummary.Parent, callSite.Position(s))
			}

			// Computing context-sensitive information for the analyses

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				// This is where a function gets "called" and the next nodes will be analyzed in a different context
				nextNode := callSite.CalleeSummary.Params[param]

				if v.interesting != nil && df.IsRecursive(cur.Trace, callSite) {
					v.interesting.signalsFor(callSite.CalleeSummary.Parent).IsRecursive = true
				}
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
				v.recordInterfaceFanout(s, callSiteFromCallStack)
				if !callSiteFromCallStack.Graph().Constructed {
					if err := v.onDemandIntraProcedural(ctx, s, callSiteFromCallStack.Graph()); err != nil {
						return err
					}
				} else if callSiteFromCallStack.Graph().IsPreSummarized {
					v.recordSummarizedReachable(s, callSiteFromCallStack.Graph().Parent, callSiteFromCallStack.Position(s))
				}
				for nextNode, edgeInfos := range callSiteFromCallStack.Out() {
					for _, edgeInfo := range edgeInfos {
						if !(graphNode.Index() >= 0 && edgeInfo.Index >= 0 && graphNode.Index() != edgeInfo.Index) {
							nextNodeWithTrace := df.NodeWithTrace{
								Node:         nextNode,
								Trace:        cur.Trace.Parent(),
								ClosureTrace: cur.ClosureTrace,
							}
							que = v.addNext(s, que, cur, callSiteFromCallStack, nextNodeWithTrace, cur.Status, edgeInfo)
						}
					}
				}
			} else if cur.ClosureTrace != nil && df.CheckClosureReturns(graphNode, cur.ClosureTrace.Label) {
				if !cur.ClosureTrace.Label.Graph().Constructed {
					if err := v.onDemandIntraProcedural(ctx, s, cur.ClosureTrace.Label.Graph()); err != nil {
						return err
					}
				} else if cur.ClosureTrace.Label.Graph().IsPreSummarized {
					v.recordSummarizedReachable(s, cur.ClosureTrace.Label.Graph().Parent, cur.ClosureTrace.Label.Position(s))
				}
				for nextNode, edgeInfos := range cur.ClosureTrace.Label.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := df.NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace.Parent(),
						}
						que = v.addNext(s, que, cur, cur.ClosureTrace.Label, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// NOTE: potential state space explosion
				// The value must always flow back to all call sites: we got here without context
				v.recordContextLossFanout(graphNode.Graph(), ContextLossCallSites, len(graphNode.Graph().Callsites))
				for _, callSite := range graphNode.Graph().Callsites {
					v.recordInterfaceFanout(s, callSite)
					if !callSite.Graph().Constructed {
						if err := v.onDemandIntraProcedural(ctx, s, callSite.Graph()); err != nil {
							return err
						}
					} else if callSite.Graph().IsPreSummarized {
						v.recordSummarizedReachable(s, callSite.Graph().Parent, callSite.Position(s))
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
			if df.SpawnsGoroutine(s, goroutines, graphNode) {
				v.recordUnsoundness(graphNode.Graph(), UnsoundnessConcurrency)
			}

			if cur.Status.Kind == df.ClosureTracing {
				currentClosure := cur.Status.CurrentClosure()
				if graphNode.CalleeSummary != nil &&
					currentClosure != nil &&
					// the following equality being true must imply that graphNode.CalleeSummary is a closure's summary
					graphNode.CalleeSummary == currentClosure {
					fv := currentClosure.Parent.FreeVars[cur.Status.TracingInfo.Index]

					if fv != nil {
						if v.interesting != nil && df.IsRecursive(cur.Trace, graphNode) {
							v.interesting.signalsFor(currentClosure.Parent).IsRecursive = true
						}
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
				trace = cur.Trace.Parent()
			}
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					// Filter outgoing edges with a type that is filtered by checking the index of the tuple
					// The index is an edge property so we can't rely on the node being filtered out.
					if df.IsFilteredType(v.taintSpec, lang.TryTupleIndexType(graphNode.Type(), edgeInfo.Index)) {
						continue
					}
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

			if !closureNode.IsReachable(s) {
				break
			}

			if !closureNode.ClosureSummary.Constructed {
				if err := v.onDemandIntraProcedural(ctx, s, closureNode.ClosureSummary); err != nil {
					return err
				}
				s.FlowGraph.Sync()
			} else if closureNode.ClosureSummary.IsPreSummarized {
				v.recordSummarizedReachable(s, closureNode.ClosureSummary.Parent, closureNode.Position(s))
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
						Trace:        cur.Trace.Parent(),
						ClosureTrace: cur.ClosureTrace.Parent(),
					}
					que = v.addNext(s, que, cur, nil, nextNodeWithTrace, cur.Status, df.EdgeInfo{})
				} else {
					s.Report.AddError(
						fmt.Sprintf("no bound variable matching free variable in %s",
							cur.ClosureTrace.Label.ClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
				}
			} else {
				// NOTE: potential state space explosion
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
						df.BuildSummary(s, f)
					}
					// This is needed to get the referring make closures outside the function
					s.FlowGraph.Sync()
				}

				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					panic(fmt.Errorf("[No Context] no referring make closure nodes from %v", graphNode))
				}

				v.recordContextLossFanout(graphNode.Graph(), ContextLossClosureSites, len(graphNode.Graph().ReferringMakeClosures))
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
				// NOTE: potential state space explosion
				v.recordContextLossFanout(graphNode.Graph(), ContextLossGlobalReads, len(graphNode.Global.ReadLocations))
				for nextNode := range graphNode.Global.ReadLocations {
					if !s.IsReachableFunction(nextNode.Graph().Parent) {
						continue
					}
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
					if !s.IsReachableFunction(nextNode.Graph().Parent) {
						continue
					}
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
			closureFn := graphNode.DestInfo().MakeClosure.Fn.(*ssa.Function)
			// The function that created the closure is not reachable, so it can't be the case
			// that the data would flow from that closure creation site.
			if !s.IsReachableFunction(closureFn) {
				break
			}
			destClosureSummary := graphNode.DestClosure()

			if destClosureSummary == nil {
				destClosureSummary = df.BuildSummary(s, closureFn)
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
			if df.IsValidatorCondition(v.taintSpec, graphNode.SsaNode().Cond, true) {
				break
			}

			cond := graphNode.SsaNode()
			pos := graphNode.Position(s)
			err := &CondError{Cond: cond, ParentName: cur.Node.ParentName(), Trace: cur.Trace.SummaryString(), Pos: pos}
			logger.Warnf("%v\n", err)
			s.Report.AddError("cond", err)
		}
	}

	if v.coverageWriter != nil {
		reportCoverage(coverage, v.coverageWriter)
	}
	return nil
}

// initEscapeAnalysisInfo initializes the information required by the escape analysis.
// This consists mainly in storing the escape graph of the function where the source appears
func (v *Visitor) initEscapeAnalysisInfo(s *df.State, source df.NodeWithTrace) {
	sourceCaller := source.Node.Graph().Parent
	var rootKey df.KeyType
	// Resolve the context
	if source.Trace != nil {
		rootKey = source.Trace.Parent().Key()
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

// recordSummarizedReachable logs and records that taint propagation reached f, whose
// summary is loaded from an external dataflow contract like user-specs, at the given position.
func (v *Visitor) recordSummarizedReachable(s *df.State, f *ssa.Function, pos token.Position) {
	if summaries.FnHasSummaries(f) {
		// Don't track pre-summarized functions that come with Argot.
		return
	}

	s.Logger.Debugf("Taint reached pre-summarized callee %s at %s\n", f.String(), pos)
}

// recordContextLossFanout records that summary's function propagated a value with no known
// calling context back to n possible call sites, closure-creation sites, or global read
// locations.
func (v *Visitor) recordContextLossFanout(summary *df.SummaryGraph, kind ContextLossKind, n int) {
	if v.interesting == nil {
		return
	}
	// A context loss to a single call site (or closure-creation site, or global read location)
	// isn't a meaningful fanout -- it's the same as having full context. Only record it once
	// there's more than one possible destination.
	if n <= 1 {
		return
	}
	sig := v.interesting.signalsFor(summary.Parent)
	loss := ContextLoss{Kind: kind, Degree: n}
	for _, existing := range sig.ContextLosses {
		if existing == loss {
			return
		}
	}
	sig.ContextLosses = append(sig.ContextLosses, loss)
}

// recordUnsoundness records that summary's function has a potential source of unsoundness. Each
// kind is recorded at most once per function: unsoundness kinds are boolean facts (did this
// happen at all), not counts.
func (v *Visitor) recordUnsoundness(summary *df.SummaryGraph, kind UnsoundnessKind) {
	if v.interesting == nil {
		return
	}
	sig := v.interesting.signalsFor(summary.Parent)
	for _, existing := range sig.Unsoundness {
		if existing == kind {
			return
		}
	}
	sig.Unsoundness = append(sig.Unsoundness, kind)
}

// recordMaxDepthExceeded records UnsoundnessMaxDepth on the nearest exported function at or
// above cur in the calling context. A private/unexported function isn't a natural target to
// write a ground-truth summary for, so we walk the call stack up (towards the source) until we
// find an exported function, and attribute the signal there instead.
func (v *Visitor) recordMaxDepthExceeded(cur *df.VisitorNode) {
	if v.interesting == nil {
		return
	}
	f := cur.Node.Graph().Parent
	trace := cur.Trace
	for f != nil && !isExportedFunction(f) {
		trace = trace.Parent()
		if trace == nil {
			return
		}
		f = trace.Label.Graph().Parent
	}
	if f == nil {
		return
	}
	sig := v.interesting.signalsFor(f)
	for _, existing := range sig.Unsoundness {
		if existing == UnsoundnessMaxDepth {
			return
		}
	}
	sig.Unsoundness = append(sig.Unsoundness, UnsoundnessMaxDepth)
}

// isExportedFunction returns true if f is an exported (public), non-synthetic function -- a
// natural target to write a ground-truth summary for.
func isExportedFunction(f *ssa.Function) bool {
	return f.Name() != "" && unicode.IsUpper(rune(f.Name()[0])) && f.Synthetic == ""
}

// recordInterfaceFanout records, on node's callee, that the callee was reached via an interface
// method call site with 10+ possible implementations. Called at every point where a *df.CallNode
// is resolved into a callee summary, regardless of traversal direction (forward into an argument,
// or backward via a call-stack unwind). If the same method was already recorded via a narrower
// interface (e.g. io.ReadCloser.Close, a strict subset of implementations of io.Closer.Close),
// the wider interface (io.Closer) replaces it, since a summary for the wider interface already
// covers every implementation of the narrower one.
func (v *Visitor) recordInterfaceFanout(s *df.State, node *df.CallNode) {
	if v.interesting == nil || node.CalleeSummary == nil {
		return
	}
	instr := node.CallSite()
	if instr == nil || !instr.Common().IsInvoke() {
		return
	}
	impls := node.Graph().Callees[instr]
	if len(impls) <= 10 {
		return
	}
	ifaceType := instr.Common().Value.Type()
	newIface, _ := ifaceType.Underlying().(*types.Interface)
	pkgPath, ifaceName := "", ifaceType.String()
	if named, ok := ifaceType.(*types.Named); ok {
		ifaceName = named.Obj().Name()
		if pkg := named.Obj().Pkg(); pkg != nil {
			pkgPath = pkg.Path()
		}
	}
	methodName := instr.Common().Method.Name()
	f := node.CalleeSummary.Parent
	sig := v.interesting.signalsFor(f)
	fanout := InterfaceFanout{
		InterfacePackage: pkgPath,
		InterfaceName:    ifaceName,
		MethodName:       methodName,
		NumImpls:         len(impls),
		Callsite:         node.Position(s).String(),
	}

	if v.interfaceTypesSeen == nil {
		v.interfaceTypesSeen = map[*ssa.Function]map[string]*types.Interface{}
	}
	seenByMethod := v.interfaceTypesSeen[f]
	if seenByMethod == nil {
		seenByMethod = map[string]*types.Interface{}
		v.interfaceTypesSeen[f] = seenByMethod
	}

	if existingIface, ok := seenByMethod[methodName]; ok && newIface != nil {
		switch {
		case types.Implements(ifaceType, existingIface):
			// The new interface implements the existing, wider one (e.g. new=ReadCloser,
			// existing=Closer): the existing entry already covers this call site, so there is
			// nothing new to record.
			return
		case types.Implements(asType(existingIface), newIface):
			// The existing interface implements the new, wider one (e.g. existing=ReadCloser,
			// new=Closer): replace the narrower entry with the wider one.
			for i, existing := range sig.InterfaceFanouts {
				if existing.MethodName == methodName {
					sig.InterfaceFanouts[i] = fanout
				}
			}
			seenByMethod[methodName] = newIface
			return
		}
	}

	for _, existing := range sig.InterfaceFanouts {
		if existing == fanout {
			return
		}
	}
	sig.InterfaceFanouts = append(sig.InterfaceFanouts, fanout)
	if newIface != nil {
		if existingIface, ok := seenByMethod[methodName]; !ok || types.Implements(asType(existingIface), newIface) {
			seenByMethod[methodName] = newIface
		}
	}
}

// asType wraps iface back into a types.Type usable with types.Implements. Since
// *types.Interface satisfies types.Type directly, this is just a type assertion helper for
// readability at call sites above.
func asType(iface *types.Interface) types.Type {
	return iface
}

// onDemandIntraProcedural runs the intra-procedural analysis on the summary, modifying its state.
// It returns an error if the analysis failed (e.g., timeout or too many values), meaning the
// result past this point is incomplete.
func (v *Visitor) onDemandIntraProcedural(ctx context.Context, s *df.State, summary *df.SummaryGraph) error {
	s.Logger.Debugf("[On-demand] Summarizing %s [%s]...", summary.Parent, lang.SafeFunctionPos(summary.Parent))
	if timeout := s.Config.DataflowProblems.IntraTimeoutMs; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer cancel()
	}

	elapsed, numValues, err := df.RunIntraProcedural(ctx, s, summary)
	s.Logger.Debugf("%-12s %-90s [%.2f s]\n", " ", summary.Parent.String(), elapsed.Seconds())
	if v.interesting != nil {
		sig := v.interesting.signalsFor(summary.Parent)
		if elapsed > sig.IntraTime {
			sig.IntraTime = elapsed
		}
		if numValues > sig.NumValues {
			sig.NumValues = numValues
		}
		unsoundness := summary.Unsoundness()
		if len(unsoundness.Recovers) > 0 {
			sig.Unsoundness = append(sig.Unsoundness, UnsoundnessRecovers)
		}
		if unsoundness.HasUnboundedDefers {
			sig.Unsoundness = append(sig.Unsoundness, UnsoundnessUnboundedDefers)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			sig.Unsoundness = append(sig.Unsoundness, UnsoundnessTimeout)
		} else if err != nil {
			sig.Unsoundness = append(sig.Unsoundness, UnsoundnessErr)
		}
	}
	if err != nil {
		s.Logger.Errorf("failed to run intra-procedural analysis on %s [%s]: %v",
			summary.Parent, lang.SafeFunctionPos(summary.Parent), err)
		return fmt.Errorf("failed to run intra-procedural analysis on %s: %w", summary.Parent, err)
	}
	return nil
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
			if df.IsValidatorCondition(v.taintSpec, condition.Value, condition.IsPositive) {
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
	if v.seen[nextVisitorNode.Key()] {
		return que
	}
	if s.Config.ExceedsMaxDepth(cur.Depth) {
		s.Logger.Debugf("Max depth (%d) exceeded at %s, not visiting %s\n",
			s.Config.UnsafeMaxDepth, cur.Node.Position(s), nextVisitorNode.Node.String())
		v.recordMaxDepthExceeded(cur)
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
			update = v.storeEscapeGraph(s, nil, nil)
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
		e := fmt.Errorf("missing escape for %s in context %s (from %s)", f, nKey, cur.Node)
		s.Logger.Error(e.Error())
		s.Logger.Debugf("%s has %d contexts", f, len(v.escapeGraphs[f]))
		s.Report.AddError(e.Error(), e)
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
			v.taints.addNewEscape(v.currentSource, instr)
			v.raiseAlarm(s, instr.Pos(),
				fmt.Sprintf("instruction %s in %s is not local because %s!\n\tPosition: %s",
					instr, node.Graph().Parent, rationale.String(), s.Program.Fset.Position(instr.Pos())))
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
		key = stack.Parent().Key()
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

	escapeNoContext := s.EscapeAnalysisState.ComputeArbitraryContext(callee)
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
		s.Logger.Warn(msg)
		v.alarms[pos] = msg
	}
}
