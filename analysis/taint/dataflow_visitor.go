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
	"strings"

	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/colors"
	"golang.org/x/tools/go/ssa"
)

type EscapeInfo struct {
	InstructionLocality map[ssa.Instruction]bool
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
	currentSource  df.NodeWithTrace
	roots          map[df.NodeWithTrace]*df.VisitorNode
	visited        map[*df.CallStack]bool
	escapeGraphs   map[*ssa.Function]map[df.KeyType]*EscapeInfo
	taints         *Flows
	coverageWriter io.StringWriter
	alarms         map[token.Pos]string
}

// NewVisitor returns a Visitor that can be used with
// [pkg/github.com/awslabs/ar-go-tools/analysis/dataflow.BuildAndRunVisitor] to run the taint analysis
// independently of the  [Analyze] function
func NewVisitor() *Visitor {
	return &Visitor{
		currentSource:  df.NodeWithTrace{},
		taints:         NewFlows(),
		coverageWriter: nil,
		roots:          map[df.NodeWithTrace]*df.VisitorNode{},
		visited:        map[*df.CallStack]bool{},
		escapeGraphs:   map[*ssa.Function]map[df.KeyType]*EscapeInfo{},
		alarms:         map[token.Pos]string{},
	}
}

// Visit runs an inter-procedural analysis to add any detected taint flow from currentSource to a sink. This implements
// the visitor interface of the dataflow package.
//
//gocyclo:ignore
func (v *Visitor) Visit(s *df.AnalyzerState, source df.NodeWithTrace) {
	ignoreNonSummarized := !s.Config.SummarizeOnDemand && s.Config.IgnoreNonSummarized
	coverage := make(map[string]bool)
	seen := make(map[df.KeyType]bool)
	goroutines := make(map[*ssa.Go]bool)
	v.currentSource = source
	logger := s.Logger
	logger.Infof("\n%s NEW SOURCE %s", strings.Repeat("*", 30), strings.Repeat("*", 30))
	logger.Infof("==> Source: %s\n", colors.Purple(v.currentSource.Node.String()))
	logger.Infof("%s %s\n", colors.Green("Found at"), v.currentSource.Node.Position(s))

	v.roots[source] = &df.VisitorNode{NodeWithTrace: source, ParamStack: nil, Prev: nil, Depth: 0}
	que := []*df.VisitorNode{v.roots[source]}

	if s.Config.UseEscapeAnalysis {
		sourceCaller := source.Node.Graph().Parent
		rootKey := source.Trace.Parent.Key()
		v.storeEscapeGraphInContext(s, sourceCaller, rootKey,
			s.EscapeAnalysisState.ComputeArbitraryContext(sourceCaller))

		escapeGraph := v.escapeGraphs[sourceCaller][rootKey]
		v.checkEscape(s, source.Node, escapeGraph)

		callNode, isCallNode := source.Node.(*df.CallNode)
		if isCallNode {
			v.storeEscapeGraph(s, source.Trace, callNode)
		}
	}

	numAlarms := 0

	// Search from path candidates in the inter-procedural flow graph from sources to sinks
	// we don't revisit only if it has been visited with the same call stack
	for len(que) != 0 {
		elt := que[0]
		que = que[1:]
		// Report coverage information for the current node
		addCoverage(s, elt, coverage)

		logger.Tracef("Visiting %T node: %v\n\tat %v\n", elt.Node, elt.Node, elt.Node.Position(s))
		logger.Tracef("Trace: %s\n", elt.Trace.String())

		// If node is sink, then we reached a sink from a source, and we must log the taint flow.
		if isSink(elt.Node, s.Config) {
			if v.taints.addNewPathCandidate(v.currentSource.Node, elt.Node) {
				numAlarms++
				reportTaintFlow(s, v.currentSource, elt)
				// Stop if there is a limit on number of alarms, and it has been reached.
				if s.Config.MaxAlarms > 0 && numAlarms >= s.Config.MaxAlarms {
					return
				}
			}
			// A sink does not have successors in the taint flow analysis (but other sinks can be reached
			// as there are still values flowing).
			continue
		}

		// If node is sanitizer, we don't want to propagate further
		// The validators will be checked in the addNext function
		if isSanitizer(elt.Node, s.Config) {
			logger.Infof("Sanitizer encountered: %s\n", elt.Node.String())
			logger.Infof("At: %s\n", elt.Node.Position(s))
			continue
		}

		// If the node is filtered out, we don't inspect children
		if isFiltered(elt.Node, s.Config) {
			continue
		}

		// Check that the node does not correspond to a non-constructed summary
		if !elt.Node.Graph().Constructed {
			if ignoreNonSummarized {
				logger.Tracef("%s: summary has not been built for %s.",
					colors.Yellow("WARNING"),
					colors.Yellow(elt.Node.Graph().Parent.Name()))

				// In that case, continue as there is no information on data flow
				continue
			}

			// If on-demand summarization is enabled, build the summary and set the node's summary to point to the
			// built summary
			v.onDemandIntraProcedural(s, elt.Node.Graph())
		}

		switch graphNode := elt.Node.(type) {

		// This is a parameter node. We have reached this node either from a function call and the stack is non-empty,
		// or we reached this node from another flow inside the function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		//- if the stack is empty, there is no calling context. The flow goes back to every possible call site of
		// the function's parameter.
		case *df.ParamNode:
			if elt.Prev != nil && elt.Prev.Node != nil {
				callArg, prevIsCallArg := elt.Prev.Node.(*df.CallNodeArg)
				if elt.Prev.Node.Graph() != graphNode.Graph() || (prevIsCallArg &&
					callArg.ParentNode().Callee() == graphNode.Graph().Parent) {
					// Flows inside the function body. The data propagates to other locations inside the function body
					// Second part of the condition allows self-recursive calls to be used
					for out, oPath := range graphNode.Out() {
						que = v.addNext(s, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
					}
				}
			}

			// Then we take care of the flows that go back to the callsite of the current function.
			// for example:
			// func f(s string, s2 *string) { *s2 = s }
			// The data can propagate from s to s2: we visit s from a callsite f(tainted, next), then
			// visit the parameter s2, and then next needs to be visited by going back to the callsite.
			if callSite := df.UnwindCallstackFromCallee(graphNode.Graph().Callsites, elt.Trace); callSite != nil {
				err := df.CheckIndex(s, graphNode, callSite, "[Unwinding callstack] Argument at call site")
				if err != nil {
					s.AddError("unwinding call stack at "+graphNode.Position(s).String(), err)
				} else {
					// Follow taint on matching argument at call site
					arg := callSite.Args()[graphNode.Index()]
					if arg != nil {
						que = v.addNext(s, que, seen, elt, arg, df.ObjectPath{}, elt.Trace.Parent, elt.ClosureTrace)
					}
				}
			} else {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					err := df.CheckIndex(s, graphNode, callSite, "[No Context] Argument at call site")
					if err != nil {
						s.AddError("argument at call site "+graphNode.String(), err)
					} else {
						callSiteArg := callSite.Args()[graphNode.Index()]
						if !callSiteArg.Graph().Constructed && !ignoreNonSummarized {
							v.onDemandIntraProcedural(s, callSiteArg.Graph())
						}
						for x, oPath := range callSiteArg.Out() {
							que = v.addNext(s, que, seen, elt, x, oPath, nil, elt.ClosureTrace)
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
				if ignoreNonSummarized {
					//
					s.ReportMissingOrNotConstructedSummary(callSite)
					break
				} else {
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
			}
			// callSite.CalleeSummary should be non-nil from now on in this branch.

			// Logic for when the summary has not been constructed
			if !callSite.CalleeSummary.Constructed {
				if ignoreNonSummarized {
					s.ReportMissingOrNotConstructedSummary(callSite)
					break
				} else {
					v.onDemandIntraProcedural(s, callSite.CalleeSummary)
				}
			}

			// Computing context-sensitive information for the analyses

			// Obtain the parameter node of the callee corresponding to the argument in the call site
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param != nil {
				// This is where a function gets "called" and the next nodes will be analyzed in a different context
				x := callSite.CalleeSummary.Params[param]

				newCallStack := elt.Trace.Add(callSite)
				v.visited[newCallStack] = true
				que = v.addNext(s, que, seen, elt, x, df.ObjectPath{}, newCallStack, elt.ClosureTrace)
			} else {
				s.AddError(
					fmt.Sprintf("no parameter matching argument at in %s", callSite.CalleeSummary.Parent.String()),
					fmt.Errorf("position %d", graphNode.Index()))
				panic("nil param")
			}

			if elt.Prev == nil || callSite.Graph() != elt.Prev.Node.Graph() {
				// We are done with propagating to the callee's parameters. Next, we need to handle
				// the flow inside the caller function: the outgoing edges computed for the summary
				for out, oPath := range graphNode.Out() {
					que = v.addNext(s, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
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
			if caller := df.UnwindCallstackFromCallee(graphNode.Graph().Callsites, elt.Trace); caller != nil {
				logger.Tracef("unwound caller: %v\n", caller)
				if !caller.Graph().Constructed {
					v.onDemandIntraProcedural(s, caller.Graph())
				}
				for x, oPath := range caller.Out() {
					if !(graphNode.Index() >= 0 && oPath.Index >= 0 && graphNode.Index() != oPath.Index) {
						que = v.addNext(s, que, seen, elt, x, oPath, elt.Trace.Parent, elt.ClosureTrace)
					}
				}
			} else if elt.ClosureTrace != nil && df.CheckClosureReturns(graphNode, elt.ClosureTrace.Label) {
				if !elt.ClosureTrace.Label.Graph().Constructed {
					v.onDemandIntraProcedural(s, elt.ClosureTrace.Label.Graph())
				}
				for cCall, oPath := range elt.ClosureTrace.Label.Out() {
					que = v.addNext(s, que, seen, elt, cCall, oPath, elt.Trace, elt.ClosureTrace.Parent)
				}
			} else if len(graphNode.Graph().Callsites) > 0 {
				// The value must always flow back to all call sites: we got here without context
				for _, callSite := range graphNode.Graph().Callsites {
					if !callSite.Graph().Constructed {
						v.onDemandIntraProcedural(s, callSite.Graph())
					}
					for x, oPath := range callSite.Out() {
						que = v.addNext(s, que, seen, elt, x, oPath, nil, elt.ClosureTrace)
					}
				}
			}
			// else, if there are no callsites this was an unreachable function

		// This is a call node, which materializes where the callee returns. A call node is reached from a return
		// from the callee. If the call stack is non-empty, the callee is removed from the stack and the data
		// flows to the children of the node.
		case *df.CallNode:
			df.CheckNoGoRoutine(s, goroutines, graphNode)
			// We pop the call from the stack and continue inside the caller
			var trace *df.NodeTree[*df.CallNode]
			if elt.Trace != nil {
				trace = elt.Trace.Parent
			}
			for x, oPath := range graphNode.Out() {
				que = v.addNext(s, que, seen, elt, x, oPath, trace, elt.ClosureTrace)
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
			for out, oPath := range graphNode.Out() {
				que = v.addNext(s, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
			}

			closureNode := graphNode.ParentNode()
			if closureNode.ClosureSummary == nil {
				if ignoreNonSummarized {
					break
				}
				closureNode.ClosureSummary = df.BuildSummary(s, closureNode.Instr().Fn.(*ssa.Function))
				logger.Tracef("closure summary parent: %v\n", closureNode.ClosureSummary.Parent)
			}

			// Flows to the free variables of the closure
			// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
			fv := closureNode.ClosureSummary.Parent.FreeVars[graphNode.Index()]
			if fv != nil {
				x := closureNode.ClosureSummary.FreeVars[fv]
				que = v.addNext(s, que, seen, elt, x, df.ObjectPath{},
					elt.Trace, elt.ClosureTrace.Add(closureNode))
			} else {
				s.AddError(
					fmt.Sprintf("no free variable matching bound variable in %s",
						closureNode.ClosureSummary.Parent.String()),
					fmt.Errorf("at position %d", graphNode.Index()))
				panic(fmt.Errorf("no free variable matching bound variable in %s at position %d",
					closureNode.ClosureSummary.Parent.String(), graphNode.Index()))
			}

		// The data flows to a free variable inside a closure body from a bound variable inside a closure definition.
		// (see the example for BoundVarNode)
		case *df.FreeVarNode:
			// Flows inside the function
			if elt.Prev.Node.Graph() != graphNode.Graph() {
				for out, oPath := range graphNode.Out() {
					que = v.addNext(s, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
				}
			} else if elt.ClosureTrace != nil {
				bvs := elt.ClosureTrace.Label.BoundVars()
				if len(bvs) == 0 {
					panic("no bound vars")
				}
				if graphNode.Index() < len(bvs) {
					bv := bvs[graphNode.Index()]
					que = v.addNext(s, que, seen, elt, bv, df.ObjectPath{}, elt.Trace, elt.ClosureTrace.Parent)
				} else {
					s.AddError(
						fmt.Sprintf("no bound variable matching free variable in %s",
							elt.ClosureTrace.Label.ClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
					panic(fmt.Errorf("no bound variable matching free variable in %s at position %d",
						elt.ClosureTrace.Label.ClosureSummary.Parent.String(), graphNode.Index()))
				}
			} else {
				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					// Summarize the free variable's closure's parent function if there is one
					f := graphNode.Graph().Parent.Parent()
					if f != nil {
						df.BuildSummary(s, f)
					}
					// This is needed to get the referring make closures outside the function
					s.FlowGraph.BuildGraph()
				}

				if len(graphNode.Graph().ReferringMakeClosures) == 0 {
					panic(fmt.Errorf("[No Context] no referring make closure nodes from %v", graphNode))
				}

				for _, makeClosureSite := range graphNode.Graph().ReferringMakeClosures {
					bvs := makeClosureSite.BoundVars()
					if graphNode.Index() < len(bvs) {
						bv := bvs[graphNode.Index()]
						que = v.addNext(s, que, seen, elt, bv, df.ObjectPath{}, elt.Trace, nil)
					} else {
						s.AddError(
							fmt.Sprintf("no bound variable matching free variable in %s",
								makeClosureSite.ClosureSummary.Parent.String()),
							fmt.Errorf("at position %d", graphNode.Index()))
						panic(fmt.Errorf("[No Context] no bound variable matching free variable in %s at position %d",
							makeClosureSite.ClosureSummary.Parent.String(), graphNode.Index()))
					}
				}
			}

		// A closure node can be reached if a function value is tainted
		// TODO: add an example
		case *df.ClosureNode:
			for out, oPath := range graphNode.Out() {
				que = v.addNext(s, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only need to follow the
		// outgoing edges. This node should only be a start node, unless some functionality is added to the df
		// graph summaries.
		case *df.SyntheticNode:
			for x, oPath := range graphNode.Out() {
				que = v.addNext(s, que, seen, elt, x, oPath, elt.Trace, elt.ClosureTrace)
			}

		case *df.AccessGlobalNode:
			if graphNode.IsWrite {
				if !ignoreNonSummarized {
					for f := range s.ReachableFunctions(false, false) {
						if lang.FnReadsFrom(f, graphNode.Global.Value()) {
							logger.Tracef("Global %v read in function: %v\n", graphNode, f)
							df.BuildSummary(s, f)
						}
					}
				}

				// Tainted data is written to ALL locations where the global is read.
				for x := range graphNode.Global.ReadLocations {
					// Global jump makes trace irrelevant if we don't follow the call graph!
					que = v.addNext(s, que, seen, elt, x, df.ObjectPath{}, nil, elt.ClosureTrace)
				}
			} else {
				// From a read location, tainted data follows the out edges of the node
				for out, oPath := range graphNode.Out() {
					que = v.addNext(s, que, seen, elt, out, oPath, elt.Trace, elt.ClosureTrace)
				}
			}

		// A BoundLabel flows to the body of the closure that captures it.
		case *df.BoundLabelNode:
			destClosureSummary := graphNode.DestClosure()
			if !ignoreNonSummarized {
				if destClosureSummary == nil {
					destClosureSummary = df.BuildSummary(s, graphNode.DestInfo().MakeClosure.Fn.(*ssa.Function))
					graphNode.SetDestClosure(destClosureSummary)
				}

				if len(graphNode.DestClosure().ReferringMakeClosures) == 0 {
					s.FlowGraph.BuildGraph()
				}
			}

			if len(destClosureSummary.ReferringMakeClosures) == 0 {
				panic(fmt.Errorf("[No Context] no referring make closure nodes from %v", graphNode))
			}

			closureNode := destClosureSummary.ReferringMakeClosures[graphNode.DestInfo().MakeClosure]
			if closureNode == nil {
				logger.Warnf("Missing closure node for bound label %v at %v\n", graphNode, graphNode.Position(s))
				break
			}
			callStackAtMakeClosure := df.UnwindCallStackToFunc(elt.Trace, closureNode.Graph().Parent)
			for _, closureCallNode := range destClosureSummary.Callsites {
				newCallStack := df.CompleteCallStackToNode(callStackAtMakeClosure, closureCallNode, s.Config.MaxDepth)
				// Flows to the free variables of the closure
				// Obtain the free variable node of the closure corresponding to the bound variable in the closure creation
				fv := destClosureSummary.Parent.FreeVars[graphNode.Index()]
				if fv != nil {
					x := destClosureSummary.FreeVars[fv]
					que = v.addNext(s,
						que,
						seen, elt, x, df.ObjectPath{},
						newCallStack,
						elt.ClosureTrace.Add(closureNode))
				} else {
					s.AddError(
						fmt.Sprintf("no free variable matching bound variable in %s", destClosureSummary.Parent.String()),
						fmt.Errorf("at position %d", graphNode.Index()))
				}
			}
		}
	}

	if v.coverageWriter != nil {
		reportCoverage(coverage, v.coverageWriter)
	}
}

// onDemandIntraProcedural runs the intra-procedural on the summary, modifying its state
// This panics when the analysis fails, because it is expected that an error will cause any further result
// to be invalid.
func (v *Visitor) onDemandIntraProcedural(s *df.AnalyzerState, summary *df.SummaryGraph) {
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
// - seen is the set of node keys that have been seen before
//
// - cur is the current visitor node
//
// - nextNode is the graph node to add to the queue
//
// - edgeInfo is the label of the edge from cur's node to toAdd
//
// - nextTrace is the trace of the visitor node that will be added with nextNode as node
//
// - nextClosureTrace is the trace of the closures that will be added with nextNode as node
func (v *Visitor) addNext(s *df.AnalyzerState,
	que []*df.VisitorNode,
	seen map[df.KeyType]bool,
	cur *df.VisitorNode,
	nextNode df.GraphNode,
	edgeInfo df.ObjectPath,
	nextTrace *df.CallStack,
	nextClosureTrace *df.NodeTree[*df.ClosureNode]) []*df.VisitorNode {

	// Check for validators
	if edgeInfo.Cond != nil && len(edgeInfo.Cond.Conditions) > 0 {
		for _, condition := range edgeInfo.Cond.Conditions {
			if isValidatorCondition(condition.IsPositive, condition.Value, s.Config) {
				s.Logger.Debugf("Validated %s.\n", condition)
				return que
			}
		}
	}

	nextNodeWithTrace := df.NodeWithTrace{Node: nextNode, Trace: nextTrace, ClosureTrace: nextClosureTrace}

	// First set of stop conditions: node has already been seen, or depth exceeds limit
	if seen[nextNodeWithTrace.Key()] || s.Config.ExceedsMaxDepth(cur.Depth) {
		return que
	}

	// If configured, use the escape analysis to scan whether data on the edge escapes
	// This controls also how recursive calls are handled.
	escapeContextUpdated := false

	if s.Config.UseEscapeAnalysis {
		escapeContextUpdated = v.manageEscapeContexts(s, cur, nextNode, nextTrace)
	}

	// Second set of stopping conditions: the escape context is unchanged on a loop path
	if nextTrace.GetLassoHandle() != nil && !escapeContextUpdated {
		return que
	}

	// logic for parameter stack
	pStack := cur.ParamStack
	switch curNode := cur.Node.(type) {
	case *df.ReturnValNode:
		pStack = pStack.Parent()
	case *df.ParamNode:
		pStack = pStack.Add(curNode)
	}

	// Adding the next node with trace in a visitor node to the queue, and recording the "execution" tree
	nextVisitorNode := &df.VisitorNode{
		NodeWithTrace: nextNodeWithTrace,
		ParamStack:    pStack,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	cur.AddChild(nextVisitorNode)
	que = append(que, nextVisitorNode)
	seen[nextNodeWithTrace.Key()] = true
	return que
}

func (v *Visitor) manageEscapeContexts(s *df.AnalyzerState, cur *df.VisitorNode, nextNode df.GraphNode,
	nextTrace *df.CallStack) bool {
	update := false

	// Update the contexts when a new function is called.
	switch curNode := cur.Node.(type) {
	case *df.CallNodeArg:
		callSite := curNode.ParentNode()
		update = v.storeEscapeGraph(s, nextTrace, callSite)
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
	} else {
		e := fmt.Errorf("missing escape for %s in context %s", f, nKey)
		s.Logger.Errorf(e.Error())
		s.Logger.Debugf("%s has %d contexts", f, len(v.escapeGraphs[f]))
		s.AddError(e.Error(), e)
	}
	return update
}

// checkEscape checks that the instructions associated to the node do not involve operations that manipulate data
// that has escape, in the state s and under the escape context escapeInfo.
func (v *Visitor) checkEscape(s *df.AnalyzerState, node df.GraphNode, escapeInfo *EscapeInfo) {
	if escapeInfo == nil { // the escapeInfo must not be nil. A missing escapeInfo means an error in the algorithm.
		s.AddError("missing escape graph",
			fmt.Errorf("was missing escape graph for node %s when checking escape", node))
	}
	for instr := range node.Marks() {
		_, isCall := instr.(ssa.CallInstruction)
		isLocal, isTracked := escapeInfo.InstructionLocality[instr]
		if !isCall && !isLocal && isTracked {
			v.taints.addNewEscape(v.currentSource.Node, instr)
			v.raiseAlarm(s, instr.Pos(),
				fmt.Sprintf("instruction %s in %s is not local!\n\tPosition: %s",
					instr, node.Graph().Parent, s.Program.Fset.Position(instr.Pos())))
		}
	}
}

// storeEscapeGraph computes the escape graph of callee in the context where it is called with stack. stack.Label should
// be the caller of callee
func (v *Visitor) storeEscapeGraph(s *df.AnalyzerState, stack *df.CallStack, callNode *df.CallNode) bool {
	if callNode == nil {
		return false
	}
	callee := callNode.Callee()

	var escapeContext *EscapeInfo

	if stack != nil {
		key := "" // key corresponding to no context if the function is a root
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

	escapeNoContext := s.EscapeAnalysisState.ComputeArbitraryContext(callee)
	v.storeEscapeGraphInContext(s, callee, nextNodeContextKey, escapeNoContext)
	return true
}

func (v *Visitor) storeEscapeGraphInContext(s *df.AnalyzerState, f *ssa.Function, key df.KeyType,
	ctx df.EscapeCallContext) {
	if v.escapeGraphs[f] == nil {
		v.escapeGraphs[f] = map[df.KeyType]*EscapeInfo{}
	}

	locality, info := s.EscapeAnalysisState.ComputeInstructionLocalityAndCallsites(f, ctx)
	v.escapeGraphs[f][key] = &EscapeInfo{locality, info}
}

// raiseAlarm raises an alarm (loags a warning message) if that alarm has not already been raised. This avoids repeated
// warning messages to the user.
func (v *Visitor) raiseAlarm(s *df.AnalyzerState, pos token.Pos, msg string) {
	if _, alreadyRaised := v.alarms[pos]; !alreadyRaised {
		s.Logger.Warnf(msg)
		v.alarms[pos] = msg
	}
}
