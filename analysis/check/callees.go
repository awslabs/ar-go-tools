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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/crillab/gophersat/maxsat"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// inferCalleeSummaries returns all the maximally-general (most data flow edges) callee summaries
// which satisfy the summary's must-not-flow requirements mustNotFlows.
// It also adds any potential sources of unsoundness to unsoundness.
func inferCalleeSummaries(
	ctx context.Context, s *State, g *dataflow.SummaryGraph,
	wantFlows []flow, mustNotFlows []flow,
	unsoundness *Unsoundness, via Method,
) (map[*ssa.Function][]summaries.DetailedSummary, error) {
	if len(g.Callees) == 0 {
		s.Logger.Tracef("function %s is a leaf function (no callees)\n", g.Parent)
		return nil, nil
	}

	if summaries.FnHasSummaries(g.Parent) {
		return nil, fmt.Errorf(
			"should not be deducing callee summaries for pre-defined function: %v", g.Parent)
	}
	if pos := s.State.Program.Fset.Position(g.Parent.Pos()); analysisutil.IsStandardLibFilename(pos.Filename) {
		s.Logger.Warnf(
			"should not be deducing callee summaries for standard library function: %v", g.Parent)
	}

	validMethods := []Method{General, Types}
	if !slices.Contains(validMethods, via) {
		return nil, fmt.Errorf("invalid inference method: want one of %v, got %v", validMethods, via)
	}

	// Compute the level of precision needed for the intra-procedural analysis.
	prec := newPrecisions(wantFlows)
	// TODO We want to use node-level precision eventually; but for now, just set the precision of
	// every node to the precision of the most-precise node (node with the longest access path).
	g.ForAllNodes(func(n dataflow.GraphNode) {
		prec.inputs.nodePathLen[n] = prec.longestPathLen
		prec.outputs.nodePathLen[n] = prec.longestPathLen
	})

	// First run the intra-procedural analysis
	if summ, ok := s.FlowGraph.Summaries[g.Parent]; ok && summ.Constructed {
		s.Logger.Tracef(
			"using already-computed intra-procedural results for function %s\n", g.Parent)
		g = summ
	} else {
		start := time.Now()
		if prec.longestPathLen == 0 {
			s.Logger.Debugf(
				"running field-insensitive intra-procedural analysis on function %s...\n", g.Parent)
			if _, err := dataflow.RunIntraProcedural(ctx, s.State, g); err != nil {
				return nil, fmt.Errorf(
					"failed to run field-insensitive intra-procedural analysis: %v", err)
			}
		} else {
			s.Logger.Debugf(
				"running field-sensitive intra-procedural analysis on function %s...\n",
				g.Parent)
			// The access path length for the values in the intra-procedural analysis must be the
			// maximum path length in prec (the precision according to the summary we are checking).
			// This is because the intra-procedural analysis specifies the precision (maximum access
			// path length) of all the values in the function at once. A smaller access path length
			// is more efficient, but we need enough precision to reason about any field-sensitive
			// flows in the summary we are checking.
			k := prec.longestPathLen
			s.Logger.Debugf("\twith path length: %d\n", k)
			s.Config.SetPathSensitiveFunc(g.Parent.String())
			// TODO We want to use node-level precision eventually; but for now, just set the
			// precision of every node to the precision of the most-precise node (node with the
			// longest access path).
			if _, err := dataflow.RunIntraProceduralFields(ctx, s.State, g, k); err != nil {
				return nil, fmt.Errorf(
					"failed to run field-sensitive intra-procedural analysis: %v", err)
			}
		}
		s.Logger.Debugf("finding unsound taint features for %s...\n", g.Parent)
		intraUnsoundness := findUnsoundDataflowFeatures(g.Parent)
		if !intraUnsoundness.isSound() {
			s.Logger.Warnf("intra-procedural taint analysis for function %s is unsound", g.Parent)
			unsoundness.DataflowFeatures = intraUnsoundness
		}
		s.Logger.Debugf(
			"intra-procedural analysis on function %s took %s\n",
			g.Parent, time.Since(start))
	}

	start := time.Now()

	traces := buildGraph(s, g, prec)
	if len(traces) == 0 {
		return nil, fmt.Errorf("no reachable traces from inputs")
	}
	s.Logger.Debugf("taint flow graph has %d reachable traces\n", len(traces))

	// unknownMayFlow are the edges that make up the callee taint flow summaries.
	unknownMayFlow := make(map[*dataflow.CallNode][]edge)
	for _, tr := range traces {
		for _, edg := range tr {
			isIntra := edg.from.call == edg.to.call
			isCallee := edg.from.call != nil
			call := edg.from.call
			if isIntra && isCallee && edg.isSoft {
				edges := unknownMayFlow[call]
				if !slices.Contains(edges, edg) {
					unknownMayFlow[call] = append(unknownMayFlow[call], edg)
				}
			}
		}
	}

	mustNotFlowEdges := mustNotFlowEdges(mustNotFlows, prec.longestPathLen)
	if s.Logger.LogsDebug() {
		for _, tr := range traces {
			dbgEdges(s, "trace from "+tr[0].from.String()+":", tr)
		}
		slices.SortFunc(mustNotFlowEdges, func(a, b edge) int {
			return strings.Compare(a.String(), b.String())
		})
		dbgEdges(s, "must-not-flow edges:", mustNotFlowEdges)
		for call, edges := range unknownMayFlow {
			dbgEdges(s, "unknown summary edges for call "+call.CallSite().String()+":", edges)
		}
	}

	// Build MaxSAT problem
	s.Logger.Debugf("computing problem constraints...")
	var constraints []maxsat.Constr
	// Callees of the same function must have identical inferred summaries
	// TODO This assumes that all nodes have the same precision.
	summaryConstrs := buildCalleeSummaryConstrs(unknownMayFlow)
	constraints = append(constraints, summaryConstrs...)
	s.Logger.Debugf("\t%d hard constraints for identical callee summaries", len(summaryConstrs))

	// Maximize unknown may-flow edges (minimize must-not-flow).
	softConstrs := buildSoftConstraints(unknownMayFlow)
	constraints = append(constraints, softConstrs...)
	s.Logger.Debugf("\t%d soft constraints for callee's may-flow edges", len(softConstrs))

	// Assert hard edges as true.
	hardConstrs := buildHardConstraints(traces)
	constraints = append(constraints, hardConstrs...)
	s.Logger.Debugf("\t%d hard constraints for known edges", len(hardConstrs))

	transitiveConstrs := buildTransitivityConstraints(traces)
	constraints = append(constraints, transitiveConstrs...)
	s.Logger.Debugf("\t%d transitivity constraints", len(transitiveConstrs))

	// Block must-not-flows
	mustNotFlowConstrs := buildMustNotFlowConstraints(traces, mustNotFlowEdges)
	constraints = append(constraints, mustNotFlowConstrs...)
	s.Logger.Debugf("\t%d must-not-flow constraints", len(mustNotFlowConstrs))
	s.Logger.Infof("... computed %d total maxsat constraints", len(constraints))

	// Find the optimal cost first
	prob := maxsat.New(constraints...)
	s.Logger.Debugf(
		"running callee summary inference for function %s...\n", g.Parent)
	startSolver := time.Now()
	model, optimalCost := prob.Solve()
	s.Logger.Infof("... maxsat solver returned after %s", time.Since(startSolver))
	if model == nil {
		// An unsatisfiable model is not necessarily an error. For example, if mustNotFlows
		// contradicts a satisfiable may-flow edge generated from a successfull intra-procedural
		// analysis, then the model will be unsatisfiable.
		s.Logger.Warnf(
			"callee summary inference MAXSAT model for function %s is unsatisfiable\n", g.Parent)
		return nil, nil
	}

	// Enumerate all optimal models and convert them to summaries
	allOptimalModels := findAllOptimalModels(model, optimalCost, constraints, unknownMayFlow)
	res, err := modelsToSummaries(s.State, allOptimalModels, unknownMayFlow)
	if err != nil {
		return nil, fmt.Errorf("failed to convert maxsat model to summaries: %v", err)
	}

	s.Logger.Debugf(
		"callee summary inference for function %s took %s\n", g.Parent, time.Since(start))

	for callee, summs := range res {
		s.Logger.Debugf("inferred summaries for callee %s:\n", callee)
		for _, summ := range summs {
			s.Logger.Debugf("\t%s\n", summ)
		}
	}

	return res, nil
}

// buildGraph builds the taint flow graph of g by tainting all of the inputs with access path length
// specified by prec.
// It returns the set of traces representing reachable flows (edges) from an input to an output.
func buildGraph(s *State, g *dataflow.SummaryGraph, prec *precisions) []trace {
	inputs := inputNodes(g, prec)
	var traces []trace
	for _, input := range inputs {
		v := &visitor{
			src:    input,
			traces: nil,
		}
		v.visit(s, input)
		traces = append(traces, v.traces...)
	}

	return traces
}

// A trace is a program path from a parent function input to an output.
// It may consist of:
//   - A hard (known) intra-procedural edge from a parent input (e.g., param) to a callee call-site
//     input (e.g., arg)
//   - A hard inter-procedural edge from a callee call-site input to its corresponding callee input
//   - A soft (unknown) intra-procedural edge from a callee input to a callee output
//   - A hard inter-procedural edge from the callee output to the corresponding call-site output
//   - A hard intra-procedural edge in the parent from the call-site output to a parent output
//
// This represents a subset of the inter-procedural taint flow graph of the parent function.
type trace []edge

func newTrace(s *dataflow.State, vn *dataflow.VisitorNode) (trace, error) {
	cur := vn
	var nodes []*dataflow.VisitorNode
	for cur != nil {
		nodes = append(nodes, cur)
		cur = cur.Prev
	}
	if len(nodes) == 0 {
		return trace{}, nil
	}
	slices.Reverse(nodes)
	if nodes[0].Trace != nil {
		return trace{}, fmt.Errorf(
			"trace source node should have nil calling context: %v, nodes: %v", nodes[0], nodes)
	}

	var tr trace
	for i := range len(nodes) - 1 {
		n := nodes[i]
		next := nodes[i+1] // guaranteed to be in bounds
		if len(n.AccessPaths) != 1 {
			return trace{}, fmt.Errorf(
				"incoming node %v should only have 1 access path, got: %v", n.Node, n.AccessPaths)
		}
		fromPath := newPath(n.AccessPaths[0], maxPathLen)
		if len(next.AccessPaths) != 1 {
			return trace{}, fmt.Errorf(
				"outgoing node %v should only have 1 access path, got: %v",
				next.Node, next.AccessPaths)
		}
		toPath := newPath(next.AccessPaths[0], maxPathLen)

		// No call trace means that no callees are reachable.
		if n.Trace == nil || next.Trace == nil {
			from := node{n.Node, nil, fromPath}
			to := node{next.Node, nil, toPath}
			tr = append(tr, newIntraHardEdge(from, to))
			continue
		}

		// Create edges:
		if n.Trace == nil && next.Trace == nil {
			// Parent intra-procedural edge (known)
			from := node{n.Node, nil, fromPath}
			to := node{next.Node, nil, toPath}
			tr = append(tr, newIntraHardEdge(from, to))
		} else if n.Trace == nil && next.Trace != nil {
			// Inter-procedural edge from parent to callee (known)
			from := node{n.Node, nil, fromPath}
			to := node{next.Node, next.Trace.Label, toPath}
			if !isInputNode(to.n) {
				return trace{}, fmt.Errorf(
					"parent->callee inter-procedural edge output %v is not a func input, partial trace: %v",
					to.n, tr)
			}
			tr = append(tr, newInterHardEdge(from, to))
		} else if n.Trace != nil && next.Trace == nil {
			// Inter-procedural edge from callee to parent (known)
			from := node{n.Node, n.Trace.Label, fromPath}
			if !isOutputNode(from.n) {
				return trace{}, fmt.Errorf(
					"callee->parent inter-procedural edge input %v is not a func output, partial trace: %v",
					from.n, tr)
			}
			to := node{next.Node, nil, toPath}
			tr = append(tr, newInterHardEdge(from, to))
		} else if n.Trace != nil && next.Trace != nil && n.Trace.Label == next.Trace.Label {
			// if n.Node.Graph().Constructed {
			// 	panic(fmt.Errorf(
			// 		"callee %v summary should not be constructed, partial trace: %v",
			// 		n.Node.Graph().Parent.String(), tr))
			// }
			// Callee intra-procedural edge
			from := node{n.Node, n.Trace.Label, fromPath}
			if !isInputNode(from.n) {
				return trace{}, fmt.Errorf(
					"callee intra-procedural edge input %v is not a func input, partial trace: %v",
					from.n, tr)
			}
			to := node{next.Node, next.Trace.Label, toPath}
			if !isOutputNode(to.n) {
				return trace{}, fmt.Errorf(
					"callee intra-procedural edge output %v is not a func output, partial trace: %v",
					to.n, tr)
			}

			if summaries.FnHasSummaries(n.Trace.Label.Callee()) {
				// The callee has a pre-defined summary, so its intra-procedural edges are known
				// (hard).
				tr = append(tr, newIntraHardEdge(from, to))
			} else if pos := s.State.Program.Fset.Position(n.Trace.Label.Callee().Pos()); analysisutil.IsStandardLibFilename(pos.Filename) {
				// ASSUMPTION: If the callee is a standard library function, it's the most-general
				// summary.
				tr = append(tr, newIntraHardEdge(from, to))
			} else {
				// Normally, the callee's summary will not exist so its intra-procedural edges are
				// unknown (soft).
				tr = append(tr, newIntraSoftEdge(from, to))
			}
		} else {
			return trace{}, fmt.Errorf("unexpected node sequence %v -> %v for partial trace: %v", n, next, tr)
		}
	}

	first := tr[0]
	last := tr[len(tr)-1]
	isStdLib := analysisutil.IsStandardLibFilename(last.to.n.Position(s).Filename)
	if first.from.call != last.to.call && !last.isSoft && !isStdLib {
		// NOTE A trace can end with a soft intra-procedural edge if the call site output of the
		// callee has no outgoing edges. This means it's trivially satisfiable but still sound.
		return trace{}, fmt.Errorf("invalid trace: different start and end calling contexts: %v", tr)
	}
	if !isInputNode(first.from.n) {
		return trace{}, fmt.Errorf(
			"invalid trace: start node is not a function input: %v", first.from)
	}
	if !isOutputNode(last.to.n) && !last.isSoft {
		return trace{}, fmt.Errorf("invalid trace: end node is not a function output: %v", last.to)
	}

	return tr, nil
}

// visitor represents a taint flow visitor that tracks all the reachable taint flow graph nodes from
// a source.
type visitor struct {
	src    *dataflow.VisitorNode
	traces []trace
	seen   map[dataflow.KeyType]bool
}

// visit *only* visits nodes in the parent.
// All callee flows are added via separate functions (called in this one).
//
//gocyclo:ignore
func (v *visitor) visit(s *State, source *dataflow.VisitorNode) error {
	v.src = source
	v.seen = make(map[dataflow.KeyType]bool)
	logger := s.Logger
	logger.Debugf("")
	logger.Debugf(" entrypoint: %s\n", formatutil.Blue(v.src.String()))
	logger.Debugf("   %s %s\n", formatutil.Green("Found at"), v.src.Node.Position(s.State))

	logger.PushContext(formatutil.Faint(v.src.Node.LongID()))
	defer logger.PopContext()

	// Initialize the stack with the outgoing edges of source (parent function input).
	var stack []*dataflow.VisitorNode
	if !source.Node.Graph().Constructed {
		return fmt.Errorf("unconstructed summary for function input: %v", source.Node)
	}
	if len(source.Node.Out()) == 0 {
		s.Logger.Warnf("no outgoing flows from function input: %v", source.Node)
	}
	for nextNode, edgeInfos := range source.Node.Out() {
		for _, edgeInfo := range edgeInfos {
			nextNodeWithTrace := dataflow.NodeWithTrace{
				Node:         nextNode,
				Trace:        nil,
				ClosureTrace: nil,
			}
			stack = v.addNextIntraParent(
				s, stack, source, nextNodeWithTrace, source.Status, edgeInfo)
		}
	}

	for len(stack) != 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		traceNode(s.State, cur)

		if cur.Trace.Len() > 1 {
			// The call stack (Trace field) of a node should never have more than one call, because
			// that means we've gone from a parent to a callee to a callee's callee (or further).
			return fmt.Errorf("node %v trace length > 1: %v", cur.Node, cur.Trace)
		}
		if cur.Node.Graph() != v.src.Node.Graph() {
			return fmt.Errorf("cannot visit callee node: %v", cur.Node)
		}

		// Base case: if we've reached an output node of the parent, add the trace.
		if isOutputNode(cur.Node) {
			tr, err := newTrace(s.State, cur)
			if err != nil {
				return fmt.Errorf("failed to create trace to node %v: %v", cur, err)
			}
			s.Logger.Tracef(
				"%sreached base case: computed trace: %v\n", strings.Repeat("  ", cur.Depth), tr)
			start := tr[0].from
			end := tr[len(tr)-1].to

			// Filter out redundant *hard* traces. If a redundant trace has soft edges, that is
			// actually good because the soft edges will be trivially satisfiable, making the
			// inferred callee summary less precise.
			hasSoftEdge := slices.ContainsFunc(tr, func(e edge) bool { return e.isSoft })
			if start.n == end.n && (start.path.isCoveredBy(end.path) || end.path.isCoveredBy(start.path)) && !hasSoftEdge {
				s.Logger.Tracef(
					"%strace input %v and output %v are redundant: skipping adding trace\n",
					strings.Repeat("  ", cur.Depth), start, end)
				continue
			}
			if !slices.ContainsFunc(v.traces, func(t trace) bool {
				// NOTE Need ContainsFunc because slices are not comparable
				if len(t) != len(tr) {
					return false
				}
				for i := range t {
					if t[i] != tr[i] {
						return false
					}
				}
				return true
			}) {
				v.traces = append(v.traces, tr)
				s.Logger.Tracef(
					"%sadded trace\n", strings.Repeat("  ", cur.Depth))
				continue
			} else {
				s.Logger.Tracef(
					"%scomputed trace is identical to a previous trace: skipped\n",
					strings.Repeat("  ", cur.Depth))
				continue
			}
		}

		// Avoid revisiting nodes with the same calling context and access paths.
		key := cur.Key()
		if v.seen[key] {
			s.Logger.Tracef(
				"%sseen node %v (path %v): stopped\n",
				strings.Repeat("  ", cur.Depth+1), cur.Node, cur.AccessPaths)
			continue
		}
		v.seen[key] = true

		// Check for recursion: don't analyze further if there's a loop in the call trace.
		if cur.Trace != nil && cur.Trace.GetLassoHandle() != nil {
			s.Logger.Tracef(
				"%snode %v trace has lasso: %v, stopped\n",
				strings.Repeat("  ", cur.Depth+1), cur.Node, cur.Trace)
			continue
		}
		// Same recursion check for closures.
		if cur.ClosureTrace != nil && cur.ClosureTrace.GetLassoHandle() != nil {
			s.Logger.Tracef(
				"%snode %v closure trace has lasso: %v, stopped\n",
				strings.Repeat("  ", cur.Depth+1), cur.Node, cur.ClosureTrace)
			continue
		}

		switch graphNode := cur.Node.(type) {

		// This is a parameter node. We have reached this node either from an entrypoint, a function
		// call and the stack is non-empty, or we reached this node from another flow inside the
		// function being called.
		// Every successor of the node must be added, and then:
		// - if the stack is non-empty, we flow back to the call-site argument.
		// - if the stack is empty, there is no calling context. The flow goes back to every
		//   possible call site of the function's parameter.
		case *dataflow.ParamNode:
			return fmt.Errorf("should not visit node %v, call stack: %v", graphNode, cur.Trace)

		// This is a call site argument. We have reached this either returning from a call, from the
		// callee's parameter node, or we reached this inside a function from another node.
		// In either case, the flow continues inside the function to the graphNode.Out() children
		// and to the callee's parameters
		case *dataflow.CallNodeArg:
			// Flow to next call
			callSite := graphNode.ParentNode()
			callee := callSite.Callee()
			if callee == nil {
				return fmt.Errorf("callsite has no callee")
			}
			callSite.CalleeSummary = dataflow.NewSummaryGraph(
				s.State, callee, dataflow.GetUniqueFunctionID(), nil, nil)
			s.FlowGraph.Summaries[callee] = callSite.CalleeSummary
			// Obtain the parameter node of the callee corresponding to the argument in the call site.
			param := callSite.CalleeSummary.Parent.Params[graphNode.Index()]
			if param == nil {
				return fmt.Errorf(
					"no parameter matching argument in %s", callSite.CalleeSummary.Parent)
			}
			calleeP := callSite.CalleeSummary.Params[param]
			calleeParamIn := &dataflow.VisitorNode{
				NodeWithTrace: dataflow.NodeWithTrace{
					Node:         calleeP,
					Trace:        cur.Trace.Add(callSite),
					ClosureTrace: cur.ClosureTrace,
				},
				Prev:        cur,
				Depth:       cur.Depth + 1,
				AccessPaths: cur.AccessPaths,
				Status:      cur.Status,
			}

			if summaries.FnHasSummaries(callee) {
				// If there's a pre-defined summary for the callee, add the outgoing caller nodes
				// according to the summary and skip analyzing the callee.
				stack = v.addNextFromPredefinedInput(s, stack, calleeParamIn, callSite)
				break
			} else {
				// If there's no pre-defined callee summary, assume that all caller outputs are
				// tainted.
				calleeOutputs := allCalleeOutputs(calleeParamIn)
				for _, calleeOutput := range calleeOutputs {
					stack = v.addCallsiteOutputs(s, stack, calleeOutput)
				}
			}

		case *dataflow.ReturnValNode:
			return fmt.Errorf("should not visit node: %v, call stack: %v", graphNode, cur.Trace)

		// This is a call node, which is reached (transitively) from a bound variable.
		case *dataflow.CallNode:
			if cur.Status.Kind == dataflow.ClosureTracing {
				// When a closure is called, taint flows to its free variables.
				currentClosure := cur.Status.CurrentClosure()
				if currentClosure == nil {
					return fmt.Errorf(
						"nil closure from call node %v in closure tracing mode", graphNode)
				}
				// NOTE This deliberately ignores any pre-constructed summaries for the callee, but
				// there should not be any if the callee is a closure.
				graphNode.CalleeSummary = dataflow.NewSummaryGraph(
					s.State, currentClosure.Parent, dataflow.GetUniqueFunctionID(), nil, nil)
				s.FlowGraph.Summaries[currentClosure.Parent] = graphNode.CalleeSummary

				if graphNode.CalleeSummary == currentClosure {
					fv := currentClosure.Parent.FreeVars[cur.Status.TracingInfo.Index]
					if fv != nil {
						fvNode := graphNode.CalleeSummary.FreeVars[fv]
						fvNode.Graph().Callsites[graphNode.CallSite()] = graphNode
						calleeInput := &dataflow.VisitorNode{
							NodeWithTrace: dataflow.NodeWithTrace{
								Node:         fvNode,
								Trace:        cur.Trace.Add(graphNode),
								ClosureTrace: cur.ClosureTrace,
							},
							Prev:        cur,
							Depth:       cur.Depth + 1,
							AccessPaths: cur.AccessPaths,
							Status:      cur.Status.PopClosure(), // Remove closure tracing mode since we've visited the closure.
						}
						// Assume that taint flows from the free variable to all callee outputs.
						calleeOutputs := allCalleeOutputs(calleeInput)
						for _, calleeOutput := range calleeOutputs {
							stack = v.addCallsiteOutputs(s, stack, calleeOutput)
						}
					} else {
						return fmt.Errorf(
							"no free variable matching bound variable in %s",
							graphNode.CalleeSummary.Parent.String())

					}
				} else {
					return fmt.Errorf("call node %v callee %v is not the current closure %v",
						graphNode, graphNode.Callee(), currentClosure.Parent)
				}
			} else {
				return fmt.Errorf("caller returned value node %v should not be visited", graphNode)
			}

		// Tainting a bound variable node means that the free variable in a closure will be tainted
		// *only when the closure is called*.
		// For example:
		// 1: x := "ok" // x is not tainted here
		// 2: f := func(s string) string { return s + x } // x is bound here
		// 3: x = source()
		// 4: sink(f("ok")) // will raise an alarm
		// The flow goes from x at line 3, to x being bound at line 2, to x the free variable
		// inside the closure definition, and finally from the return of the closure to the
		// call site of the closure inside a sink.
		// For more examples with closures, see testdata/src/taint/inter-procedural/closures/main.go
		case *dataflow.BoundVarNode:
			closureNode := graphNode.ParentNode()
			if !closureNode.IsReachable(s.State) {
				break
			}
			closureFn := closureNode.Instr().Fn.(*ssa.Function) // guaranteed not to panic
			if closureFn == nil {
				return fmt.Errorf(
					"no function for closure %v of bound var %v", closureNode, graphNode)
			}
			// NOTE This deliberately ignores any pre-constructed summaries for the closure.
			closureNode.ClosureSummary = dataflow.NewSummaryGraph(
				s.State, closureFn, dataflow.GetUniqueFunctionID(), nil, nil)
			s.FlowGraph.Summaries[closureFn] = closureNode.ClosureSummary

			newTrace := cur.Trace
			if cur.Trace != nil && cur.Trace.Label != nil {
				newTrace = dataflow.UnwindCallStackToFunc(cur.Trace, closureFn)
			}
			closureNodeWithTrace := dataflow.NodeWithTrace{
				Node:         closureNode,
				Trace:        newTrace,
				ClosureTrace: cur.ClosureTrace.Add(closureNode),
			}

			stack = v.addNextIntraParent(s, stack, cur, closureNodeWithTrace,
				dataflow.VisitorNodeStatus{
					Kind:        dataflow.ClosureTracing,
					TracingInfo: cur.Status.TracingInfo.Next(closureNode.ClosureSummary, graphNode.Index()),
				},
				dataflow.EdgeInfo{})

		// The data flows to a free variable inside a closure body from a bound variable inside a
		// closure definition.
		// (see the example for BoundVarNode)
		// The data can also flow from the function body to the free var node, in which case it
		// implies the bound variable (in the caller) is tainted after the function returns.
		case *dataflow.FreeVarNode:
			return fmt.Errorf("node should not be visited: %v", graphNode)

		// A closure node is usually reached when the visitor is tracing a specific closure
		case *dataflow.ClosureNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNextIntraParent(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

		// Synthetic nodes can only be sources and data should only flow from those nodes: we only
		// need to follow the outgoing edges. This node should only be a start node, unless some
		// functionality is added to the dataflow graph summaries.
		case *dataflow.SyntheticNode, *dataflow.BuiltinCallNode:
			for nextNode, edgeInfos := range graphNode.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         nextNode,
						Trace:        cur.Trace,
						ClosureTrace: cur.ClosureTrace,
					}
					stack = v.addNextIntraParent(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo)
				}
			}

		case *dataflow.AccessGlobalNode:
			if graphNode.IsWrite {
				s.Logger.Warnf("unanalyzed write to global node: %v\n", graphNode)
			} else {
				// From a read location, tainted data follows the out edges of the node
				for nextNode, edgeInfos := range graphNode.Out() {
					if !s.IsReachableFunction(nextNode.Graph().Parent) {
						continue
					}
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := dataflow.NodeWithTrace{
							Node:         nextNode,
							Trace:        cur.Trace,
							ClosureTrace: cur.ClosureTrace,
						}
						stack = v.addNextIntraParent(s, stack, cur, nextNodeWithTrace, cur.Status, edgeInfo)
					}
				}
			}

		case *dataflow.BoundLabelNode:
			// TODO Figure out how to handle bound labels
			continue
		case *dataflow.IfNode:
			continue
		default:
			return fmt.Errorf("unhandled graph node type: %T", graphNode)
		}
	}

	return nil
}

// addNextIntraParent represents an intra-procedural taint flow in the parent.
// It adds the node to the stack, setting cur as the previous node and checking that node with
// the trace (call context) has not been seen before.
//   - stack is the DFS stack in the calling algorithm
//   - cur is the current visitor node
//   - intermediateNode is an intermediate node to be inserted for tracing purposes
//   - nextNodeWithTrace is the graph node to add to the stack, with the new call stack trace and
//     closure stack trace
//   - nextStatus is the status for the next node that will be added
//   - edgeInfo is the label of the edge from cur's node to the next node
//
//gocyclo:ignore
func (v *visitor) addNextIntraParent(
	s *State, stack []*dataflow.VisitorNode,
	cur *dataflow.VisitorNode, nextNodeWithTrace dataflow.NodeWithTrace,
	nextStatus dataflow.VisitorNodeStatus, edgeInfo dataflow.EdgeInfo,
) []*dataflow.VisitorNode {
	if cur.Trace != nil {
		s.Logger.Errorf(
			"cannot add intra-procedural flows from callee node: %v, trace: %v", cur, cur.Trace)
		return stack
	}

	nextNodeAccessPaths := findMatchingPaths(cur, nextNodeWithTrace, edgeInfo)
	// No matching access paths for this edge
	if len(nextNodeAccessPaths) == 0 {
		return stack
	}

	// Create a new node for each matching access path.
	for _, accessPath := range nextNodeAccessPaths {
		// Adding the next node with trace in a visitor node to the stack, and recording the
		// "execution" tree
		nextVisitorNode := &dataflow.VisitorNode{
			NodeWithTrace: nextNodeWithTrace,
			AccessPaths:   []string{accessPath},
			Status:        nextStatus,
			Prev:          cur,
			Depth:         cur.Depth + 1,
		}

		// NOTE For consistency, the stopping conditions are in the beginning of the visitor loop.
		// This is different from the taint analysis implementation.

		stack = append(stack, nextVisitorNode)
		s.Logger.Tracef(
			"%sadded intra next node: %v\n",
			strings.Repeat("  ", cur.Depth+1), nextVisitorNode)
	}

	return stack
}

func findMatchingPaths(
	cur *dataflow.VisitorNode, next dataflow.NodeWithTrace, edgeInfo dataflow.EdgeInfo,
) []string {
	if len(cur.AccessPaths) != 1 {
		fmt.Printf("[ERROR] node %v should only have 1 access path", cur)
		return nil
	}

	var nextPaths []string
	curPath := cur.AccessPaths[0]
	// If cur is field-insensitive, then the next node should be field-insensitive.
	if len(curPath) == 0 {
		return []string{""}
	}

	if len(edgeInfo.RelPath) == 0 {
		// If there's no edge information, this is likely an inter-procedural flow or a callee
		// intra-procedural flow. Enumerate all the possible access paths with a maximum length of
		// of the current access path.
		//
		// HACK newPath is the easiest way to compute the access path length for now since the
		// dataflow analysis processes them as strings.
		curLen := newPath(curPath, maxPathLen).len()
		edgeInfo.RelPath = make(map[string]map[string]bool)
		edgeInfo.RelPath[curPath] = make(map[string]bool)
		if cur.Node.Graph() == next.Node.Graph() {
			// If this is an intra-procedural flow, then enumerate all the possible outgoing access
			// paths.
			nextPaths := leafPathsUpTo(next.Node.Type(), curLen)
			for _, nextPath := range nextPaths {
				edgeInfo.RelPath[curPath][nextPath.String()] = true
			}
		} else {
			// If this is an inter-procedural flow, then the outgoing access path is the incoming
			// access path.
			edgeInfo.RelPath[curPath][curPath] = true
		}
	}

	for inPath, outPaths := range edgeInfo.RelPath {
		if strings.HasPrefix(inPath, curPath) {
			for outPath := range outPaths {
				nextPaths = append(nextPaths, outPath)
			}
		}
	}

	return nextPaths
}

// addCallsiteOutputs represents an inter-procedural taint flow from the callee input to the callee
// output to the call-site output's outgoing nodes.
//
//gocyclo:ignore
func (v *visitor) addCallsiteOutputs(
	s *State, stack []*dataflow.VisitorNode, calleeOutput *dataflow.VisitorNode,
) []*dataflow.VisitorNode {
	prevStackLen := len(stack)
	defer func() {
		if len(stack) == prevStackLen {
			// If there are no intra-procedural flows from the output value in the call site, that
			// means the value is never used in the caller. We need the soft intra-procedural edge
			// representing this inferred callee flow to be trivially satisfiable so that we don't
			// need to prove any of its must-not-flows later.
			//
			// Create a new trace ending with the callee output node.
			tr, err := newTrace(s.State, calleeOutput)
			if err != nil {
				s.Logger.Errorf("failed to create trace: %v", err)
				return
			}
			v.traces = append(v.traces, tr)
			s.Logger.Tracef(
				"%s...did not add any outgoing nodes from callee output %v: added new trace %v",
				strings.Repeat("  ", calleeOutput.Depth), calleeOutput, tr)
		}
	}()

	switch n := calleeOutput.Node.(type) {
	case *dataflow.ParamNode:
		// Taint flows inter-procedurally from the callee param to the call site argument.
		// Then it flows to all the call site argument's outgoing nodes.
		if calleeOutput.Trace != nil && calleeOutput.Trace.Label != nil {
			callSite := calleeOutput.Trace.Label
			if !callSite.Graph().Constructed {
				s.Logger.Errorf(
					"call site %v of return node %v graph is not constructed",
					callSite, n)
				return stack
			}
			arg := callSite.Args()[n.Index()]
			if arg == nil {
				s.Logger.Errorf(
					"no matching arg from param %v in call site %v", n, callSite)
				return stack
			}
			callerOutput := &dataflow.VisitorNode{
				NodeWithTrace: dataflow.NodeWithTrace{
					Node:         arg,
					Trace:        calleeOutput.Trace.Parent(),
					ClosureTrace: calleeOutput.ClosureTrace,
				},
				Prev:        calleeOutput,
				Depth:       calleeOutput.Depth + 1,
				AccessPaths: calleeOutput.AccessPaths,
				Status:      calleeOutput.Status,
			}
			s.Logger.Tracef(
				"%sadding callee -> caller inter-procedural flow: %v -> %v\n",
				strings.Repeat("  ", callerOutput.Depth), calleeOutput, callerOutput)
			for nextNode, edgeInfos := range arg.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         nextNode,
						Trace:        callerOutput.Trace,
						ClosureTrace: callerOutput.ClosureTrace,
					}
					stack = v.addNextIntraParent(
						s, stack, callerOutput, nextNodeWithTrace, callerOutput.Status, edgeInfo)
				}
			}
		} else {
			s.Logger.Errorf(
				"lost context of param %v in %v", calleeOutput.Node, calleeOutput.Node.ParentName())
			return stack
		}
	case *dataflow.ReturnValNode:
		// Taint flows inter-procedurally from the return value in the callee to the callsite call
		// node (the value returned from the callee to the caller). It then flows intra-procedurally
		// to all the outgoing nodes from the call node.
		if calleeOutput.Trace != nil && calleeOutput.Trace.Label != nil {
			callSite := calleeOutput.Trace.Label
			if !callSite.Graph().Constructed {
				s.Logger.Errorf(
					"call site %v of return node %v graph is not constructed",
					callSite, n)
				return stack
			}
			callerOutput := &dataflow.VisitorNode{
				NodeWithTrace: dataflow.NodeWithTrace{
					Node:         callSite,
					Trace:        calleeOutput.Trace.Parent(),
					ClosureTrace: calleeOutput.ClosureTrace,
				},
				Prev:        calleeOutput,
				Depth:       calleeOutput.Depth + 1,
				AccessPaths: calleeOutput.AccessPaths,
				Status:      calleeOutput.Status,
			}
			s.Logger.Tracef(
				"%sadding callee -> caller inter-procedural flow: %v -> %v\n",
				strings.Repeat("  ", callerOutput.Depth), calleeOutput, callerOutput)
			for nextNode, edgeInfos := range callSite.Out() {
				for _, edgeInfo := range edgeInfos {
					if !(n.Index() >= 0 && edgeInfo.Index >= 0 && n.Index() != edgeInfo.Index) {
						// Only flow to return values with the same index.
						nextNodeWithTrace := dataflow.NodeWithTrace{
							Node:         nextNode,
							Trace:        callerOutput.Trace,
							ClosureTrace: callerOutput.ClosureTrace,
						}
						stack = v.addNextIntraParent(
							s, stack, callerOutput, nextNodeWithTrace, callerOutput.Status, edgeInfo)
					} else {
						s.Logger.Tracef(
							"edge from %v does not match: %v via %v\n",
							calleeOutput, nextNode, edgeInfo)
					}
				}
			}
		} else if calleeOutput.ClosureTrace != nil && calleeOutput.ClosureTrace.Label != nil {
			closure := calleeOutput.ClosureTrace.Label
			if closure.ClosureSummary == nil {
				s.Logger.Errorf(
					"closure summary from %v via trace %v is nil", n, calleeOutput.ClosureTrace)
				return stack
			}
			if !dataflow.CheckClosureReturns(n, closure) {
				s.Logger.Errorf(
					"return node %v is not from the closure %v in the trace", n, closure)
				return stack
			}
			if !closure.Graph().Constructed {
				s.Logger.Errorf(
					"closure node %v of return node %v graph is not constructed", closure, n)
				return stack
			}
			callerOutput := &dataflow.VisitorNode{
				NodeWithTrace: dataflow.NodeWithTrace{
					Node:         closure,
					Trace:        calleeOutput.Trace,
					ClosureTrace: calleeOutput.ClosureTrace.Parent(),
				},
				Prev:        calleeOutput,
				Depth:       calleeOutput.Depth + 1,
				AccessPaths: calleeOutput.AccessPaths,
				Status:      calleeOutput.Status,
			}
			s.Logger.Tracef(
				"%sadding callee -> caller inter-procedural flow: %v -> %v\n",
				strings.Repeat("  ", callerOutput.Depth), calleeOutput, callerOutput)
			for nextNode, edgeInfos := range closure.Out() {
				for _, edgeInfo := range edgeInfos {
					nextNodeWithTrace := dataflow.NodeWithTrace{
						Node:         nextNode,
						Trace:        callerOutput.Trace,
						ClosureTrace: callerOutput.ClosureTrace,
					}
					stack = v.addNextIntraParent(
						s, stack, callerOutput, nextNodeWithTrace, calleeOutput.Status, edgeInfo)
				}
			}
		} else {
			s.Logger.Errorf("no calling context for callee output: %v", calleeOutput)
			return stack
		}
	case *dataflow.FreeVarNode:
		if calleeOutput.ClosureTrace != nil && calleeOutput.ClosureTrace.Label != nil {
			// Flow inter-procedurally to the corresponding bound variable from the closure trace.
			bvs := calleeOutput.ClosureTrace.Label.BoundVars()
			if len(bvs) == 0 {
				s.Logger.Errorf("no bound vars for node %v", n)
				return stack
			}
			if n.Index() < len(bvs) {
				bv := bvs[n.Index()]
				callerOutput := &dataflow.VisitorNode{
					NodeWithTrace: dataflow.NodeWithTrace{
						Node:         bv,
						Trace:        calleeOutput.Trace.Parent(),
						ClosureTrace: calleeOutput.ClosureTrace.Parent(),
					},
					Prev:        calleeOutput,
					Depth:       calleeOutput.Depth + 1,
					AccessPaths: calleeOutput.AccessPaths,
					Status:      calleeOutput.Status.PopClosure(),
				}
				s.Logger.Tracef(
					"%sadding callee -> caller inter-procedural flow: %v -> %v\n",
					strings.Repeat("  ", callerOutput.Depth), calleeOutput, callerOutput)
				for nextNode, edgeInfos := range bv.Out() {
					for _, edgeInfo := range edgeInfos {
						nextNodeWithTrace := dataflow.NodeWithTrace{
							Node:         nextNode,
							Trace:        callerOutput.Trace,
							ClosureTrace: callerOutput.ClosureTrace,
						}
						stack = v.addNextIntraParent(
							s, stack, callerOutput, nextNodeWithTrace, callerOutput.Status, edgeInfo)
					}
				}
			} else {
				s.Logger.Errorf("no bound variable matching free variable in %s",
					calleeOutput.ClosureTrace.Label.ClosureSummary.Parent.String())
				return stack
			}
		} else {
			// There is no closure trace so flow to the corresponding bound variable in each closure
			// that may refer to the free variable.
			s.Logger.Warnf("no closure trace for node %v\n", calleeOutput)
			// Build the inter-procedural data-flow graph, using contracts and predefined stdlib
			// summaries when available.
			s.FlowGraph.BuildGraph(true)
			s.FlowGraph.Sync()
			if len(n.Graph().ReferringMakeClosures) == 0 {
				f := n.Graph().Parent.Parent()
				if !s.IsReachableFunction(f) {
					// We're not even in a reachable function, so the data cannot be flowing
					// here. We might have reached this point by moving through bound/global
					// variables but the function is not actually reachable.
					return stack
				}
				s.Logger.Errorf(
					"no closure context: no referring make closure nodes from %v", n)
				return stack
			}

			for _, makeClosureSite := range n.Graph().ReferringMakeClosures {
				bvs := makeClosureSite.BoundVars()
				if len(bvs) == 0 {
					s.Logger.Errorf("no bound vars for node %v", n)
					return stack
				}
				if n.Index() < len(bvs) {
					bv := bvs[n.Index()]
					callerOutput := &dataflow.VisitorNode{
						NodeWithTrace: dataflow.NodeWithTrace{
							Node:         bv,
							Trace:        calleeOutput.Trace.Parent(),
							ClosureTrace: calleeOutput.ClosureTrace.Parent(),
						},
						Prev:        calleeOutput,
						Depth:       calleeOutput.Depth + 1,
						AccessPaths: calleeOutput.AccessPaths,
						Status:      calleeOutput.Status.PopClosure(),
					}
					s.Logger.Tracef(
						"%sadding callee -> caller inter-procedural flow: %v -> %v\n",
						strings.Repeat("  ", callerOutput.Depth), calleeOutput, callerOutput)
					for nextNode, edgeInfos := range bv.Out() {
						for _, edgeInfo := range edgeInfos {
							nextNodeWithTrace := dataflow.NodeWithTrace{
								Node:         nextNode,
								Trace:        callerOutput.Trace,
								ClosureTrace: calleeOutput.ClosureTrace,
							}
							stack = v.addNextIntraParent(
								s, stack, callerOutput, nextNodeWithTrace,
								calleeOutput.Status, edgeInfo)
						}
					}
				} else {
					s.Logger.Errorf("no bound variable matching free variable in %s",
						calleeOutput.ClosureTrace.Label.ClosureSummary.Parent.String())
					return stack
				}
			}
		}
	case *dataflow.AccessGlobalNode:
		// s.Logger.Errorf("TODO global read analysis for node %v in %v\n", n, n.ParentName())
	default:
		s.Logger.Errorf("invalid output node type: %T", n)
		return stack
	}

	return stack
}

func (v *visitor) addNextFromPredefinedInput(
	s *State, stack []*dataflow.VisitorNode,
	calleeParamIn *dataflow.VisitorNode, callSite *dataflow.CallNode,
) []*dataflow.VisitorNode {
	calleeParamNode, ok := calleeParamIn.Node.(*dataflow.ParamNode)
	if !ok {
		s.Logger.Errorf(
			"can only add predefined summary input flows from a callee param, got: %v",
			calleeParamIn.Node)
		return stack
	}

	callee := callSite.Callee()
	// If there is a pre-defined summary, follow the taint flow from it directly.
	summ, ok := summaries.SummaryOfFunc(callee)
	if !ok {
		s.Logger.Errorf("expected pre-defined function %s to have a summary", callee)
		return stack
	}
	s.Logger.Tracef("pre-defined summary for callee %v: %v\n", callee, summ)

	// Add flows to the corresponding tainted arguments.
	argFlows, err := summ.GetArgFlows(callee)
	if err != nil {
		s.Logger.Errorf("failed to get arg flows for pre-defined summary %v", summ)
		return stack
	}
	if len(argFlows) <= calleeParamNode.Index() {
		s.Logger.Debugf("no arg flows for param %v in pre-defined summary %v", calleeParamNode, summ)
		return stack
	}
	taintedArgIdxs := argFlows[calleeParamNode.Index()]
	for _, nextArgIdx := range taintedArgIdxs {
		nextArg := callSite.Args()[nextArgIdx]
		var calleeOutput *dataflow.ParamNode
		for _, param := range callSite.CalleeSummary.Params {
			if param.Index() == nextArgIdx {
				calleeOutput = param
				break
			}
		}
		if calleeOutput == nil {
			s.Logger.Errorf(
				"no corresponding param for arg %v in pre-defined callee summary %v",
				nextArg, callSite.CalleeSummary)
			return nil
		}
		callerOutput := &dataflow.VisitorNode{
			NodeWithTrace: dataflow.NodeWithTrace{
				Node:         nextArg,
				Trace:        nil, // Popped the call stack from the callee (Prev node).
				ClosureTrace: calleeParamIn.ClosureTrace,
			},
			Prev: &dataflow.VisitorNode{
				NodeWithTrace: dataflow.NodeWithTrace{
					Node:         calleeOutput,
					Trace:        calleeParamIn.Trace,
					ClosureTrace: calleeParamIn.ClosureTrace,
				},
				Prev:        calleeParamIn,
				Depth:       calleeParamIn.Depth + 1,
				AccessPaths: calleeParamIn.AccessPaths,
				Status:      calleeParamIn.Status,
			},
			Depth:       calleeParamIn.Depth + 2,
			AccessPaths: calleeParamIn.AccessPaths,
			Status:      calleeParamIn.Status,
		}
		s.Logger.Tracef(
			"%sadding callee -> caller inter-procedural flow: %v -> %v\n",
			strings.Repeat("  ", callerOutput.Depth), calleeOutput, callerOutput)
		for nextNode, edgeInfos := range callerOutput.Node.Out() {
			for _, edgeInfo := range edgeInfos {
				nextNodeWithTrace := dataflow.NodeWithTrace{
					Node:         nextNode,
					Trace:        callerOutput.Trace,
					ClosureTrace: callerOutput.ClosureTrace,
				}
				stack = v.addNextIntraParent(
					s, stack, callerOutput, nextNodeWithTrace,
					callerOutput.Status, edgeInfo)
			}
		}
	}

	// Add flows to the corresponding tainted return values.
	retFlows, err := summ.GetReturnFlows(callee)
	if err != nil {
		s.Logger.Errorf("failed to get return flows for pre-defined summary %v", summ)
		return stack
	}
	if len(retFlows) <= calleeParamNode.Index() {
		s.Logger.Debugf("no ret flows for param %v in pre-defined summary %v", calleeParamNode, summ)
		return stack
	}
	taintedRetIdxs := retFlows[calleeParamNode.Index()]
	for _, retIdx := range taintedRetIdxs {
		var callerRets []dataflow.NodeWithTrace
		for nextNode, edgeInfos := range callSite.Out() {
			for _, ei := range edgeInfos {
				if !(retIdx >= 0 && ei.Index >= 0 && retIdx != ei.Index) {
					// Only flow to returned values in the caller with the same tainted return index.
					next := dataflow.NodeWithTrace{
						Node:         nextNode,
						Trace:        nil,
						ClosureTrace: calleeParamIn.ClosureTrace,
					}
					callerRets = append(callerRets, next)
				}
			}
		}
		// Since a callee summary contains flows to *a* return node with a matching index, it
		// doesn't really matter which callee return node is in the trace. Just pick the first one
		// that matches.
		var nextCalleeRet *dataflow.ReturnValNode
		for _, rets := range callSite.CalleeSummary.Returns {
			if nextCalleeRet != nil {
				break
			}
			for _, ret := range rets {
				if ret.Index() == retIdx {
					nextCalleeRet = ret
					break
				}
			}
		}
		if nextCalleeRet == nil {
			s.Logger.Errorf(
				"no corresponding ret for caller rets %v in pre-defined callee summary %v",
				callerRets, callSite.CalleeSummary)
			return nil
		}
		for _, callerRet := range callerRets {
			nextNode := &dataflow.VisitorNode{
				NodeWithTrace: callerRet,
				Prev: &dataflow.VisitorNode{
					NodeWithTrace: dataflow.NodeWithTrace{
						Node:         nextCalleeRet,
						Trace:        nil, // Popped the call stack from the callee (Prev node).
						ClosureTrace: calleeParamIn.ClosureTrace,
					},
					Prev:        calleeParamIn,
					Depth:       calleeParamIn.Depth + 1,
					AccessPaths: calleeParamIn.AccessPaths,
					Status:      calleeParamIn.Status,
				},
				Depth:       calleeParamIn.Depth + 2,
				AccessPaths: calleeParamIn.AccessPaths,
				Status:      calleeParamIn.Status,
			}
			stack = append(stack, nextNode)
		}
	}

	return stack
}

func inputNodes(g *dataflow.SummaryGraph, prec *precisions) []*dataflow.VisitorNode {
	// TODO Use static analyses to filter some?
	var inputs []*dataflow.VisitorNode
	g.ForAllNodes(func(n dataflow.GraphNode) {
		if isInputNode(n) {
			var pl int
			if len(prec.inputs.nodePathLen) > 0 {
				if k, ok := prec.inputs.nodePathLen[n]; ok {
					pl = k
				} else {
					// If some flows in the summary are field-sensitive but n is not in nodePathLen,
					// then it should be field-insensitive.
					pl = 0
				}
			}
			paths := leafPathsUpTo(n.Type(), pl)
			for _, path := range paths {
				in := &dataflow.VisitorNode{
					NodeWithTrace: dataflow.NodeWithTrace{
						Node:         n,
						Trace:        nil,
						ClosureTrace: nil,
					},
					Prev:        nil,
					AccessPaths: []string{path.String()},
					Status:      dataflow.VisitorNodeStatus{Kind: dataflow.DefaultTracing},
				}
				inputs = append(inputs, in)
			}
		}
	})

	return inputs
}

func allCalleeOutputs(calleeIn *dataflow.VisitorNode) []*dataflow.VisitorNode {
	// TODO Use static analyses to filter some?
	var outputs []*dataflow.VisitorNode
	g := calleeIn.Node.Graph()
	g.ForAllNodes(func(n dataflow.GraphNode) {
		if isOutputNode(n) {
			if param, ok := n.(*dataflow.ParamNode); ok {
				if !isPointerLike(param.Type()) {
					return
				}
			}

			pl := newPath(calleeIn.AccessPaths[0], maxPathLen).len()
			paths := leafPathsUpTo(n.Type(), pl)
			for _, path := range paths {
				out := &dataflow.VisitorNode{
					NodeWithTrace: dataflow.NodeWithTrace{
						Node:         n,
						Trace:        calleeIn.Trace, // trace is the same because it's intra-procedural
						ClosureTrace: calleeIn.ClosureTrace,
					},
					Prev:        calleeIn,
					Depth:       calleeIn.Depth + 1,
					AccessPaths: []string{path.String()},
					Status:      calleeIn.Status,
				}
				if out.Node == calleeIn.Node && out.AccessPaths[0] == calleeIn.AccessPaths[0] {
					// Skip self flows.
					continue
				}
				outputs = append(outputs, out)
			}
		}
	})

	return outputs
}

// buildCalleeSummaryConstrs returns the constraints to ensure that unknown edges for different
// callsites with the same callee are the same.
func buildCalleeSummaryConstrs(unknown map[*dataflow.CallNode][]edge) []maxsat.Constr {
	var summaryConstrs []maxsat.Constr
	for call := range unknown {
		edges := unknown[call]
		for otherCall := range unknown {
			if call == otherCall {
				continue
			}
			if call.Callee() != otherCall.Callee() {
				continue
			}

			otherEdges := unknown[otherCall]

			// Match edges semantically, not by position
			// Create a map from edge signature to edge for matching
			edgeMap := make(map[string]edge)
			for _, e := range edges {
				sig := edgeSignature(e)
				edgeMap[sig] = e
			}

			for _, otherE := range otherEdges {
				sig := edgeSignature(otherE)
				if e, ok := edgeMap[sig]; ok {
					// These edges correspond semantically
					// Constraint ensures e <-> otherE (in CNF)
					constrs := []maxsat.Constr{
						maxsat.HardClause(
							newMayFlowLit(e).Negation(),
							newMayFlowLit(otherE),
						),
						maxsat.HardClause(
							newMayFlowLit(otherE).Negation(),
							newMayFlowLit(e),
						),
					}
					summaryConstrs = append(summaryConstrs, constrs...)
				}
			}
		}
	}

	return summaryConstrs
}

// buildSoftConstraints returns the constraints to maximize the soft (unknown) edges.
func buildSoftConstraints(unknownMayFlow map[*dataflow.CallNode][]edge) []maxsat.Constr {
	var maxConstrs []maxsat.Constr
	for _, edges := range unknownMayFlow {
		for _, e := range edges {
			constr := maxsat.SoftClause(newMayFlowLit(e))
			maxConstrs = append(maxConstrs, constr)
		}
	}
	return maxConstrs
}

// buildHardConstraints returns the constraints for hard (known) edges, asserting them as true.
func buildHardConstraints(traces []trace) []maxsat.Constr {
	var constraints []maxsat.Constr
	hardEdgeSeen := make(map[string]struct{})
	for _, tr := range traces {
		for _, e := range tr {
			if !e.isSoft {
				lit := newMayFlowLit(e)
				if _, ok := hardEdgeSeen[lit.Var]; !ok {
					hardEdgeSeen[lit.Var] = struct{}{}
					constraints = append(constraints, maxsat.HardClause(lit))
				}
			}
		}
	}
	return constraints
}

// buildTransitivityConstraints returns a list of constraints representing the parent input/output
// flows, where if all unknown edges are true, then the input->output flow of the trace is true.
func buildTransitivityConstraints(traces []trace) []maxsat.Constr {
	var transitiveConstrs []maxsat.Constr
	for _, tr := range traces {
		if len(tr) < 2 {
			continue
		}
		a := tr[0].from
		z := tr[len(tr)-1].to

		// Collect the soft (unknown) edges in this trace.
		var softLits []maxsat.Lit
		for _, e := range tr {
			if e.isSoft {
				softLits = append(softLits, newMayFlowLit(e).Negation())
			}
		}
		if len(softLits) == 0 || a == z {
			continue
		}

		// If all soft edges are true, then the end-to-end flow must be true.
		// CNF: ¬s1 ∨ ¬s2 ∨ ... ∨ (a→z)
		lits := append(softLits, newMayFlowLit(edge{from: a, to: z}))
		transitiveConstrs = append(transitiveConstrs, maxsat.HardClause(lits...))
	}

	return transitiveConstrs
}

// buildMustNotFlowConstraints returns the constraints that block must-not-flows.
//
// Since traces contains all the reachable traces from inputs to the function, we only need to block
// traces that are implied by the must-not-flows.
func buildMustNotFlowConstraints(traces []trace, mustNotFlows []edge) []maxsat.Constr {
	var constrs []maxsat.Constr
	seen := make(map[edge]struct{})
	for _, tr := range traces {
		for _, mnf := range mustNotFlows {
			start := tr[0].from
			end := tr[len(tr)-1].to
			if start.n == mnf.from.n && end.n == mnf.to.n {
				if start.path.isCoveredBy(mnf.from.path) && end.path.isCoveredBy(mnf.to.path) {
					edg := newIntraHardEdge(start, end)
					if _, ok := seen[edg]; ok {
						continue
					}
					seen[edg] = struct{}{}
					lit := newMayFlowLit(edg).Negation()
					constrs = append(constrs, maxsat.HardClause(lit))
					break
				}
			}
		}
	}

	return constrs
}

func findAllOptimalModels(
	model maxsat.Model, optimalCost int, constraints []maxsat.Constr,
	unknown map[*dataflow.CallNode][]edge,
) []maxsat.Model {
	// Get all unknown edge variable names for blocking
	unknownVars := make(map[string]bool)
	for _, edges := range unknown {
		for _, e := range edges {
			unknownVars[newMayFlowLit(e).Var] = true
		}
	}

	// Collect all models with the optimal cost
	allOptimalModels := []maxsat.Model{model}
	// Enumerate all other optimal solutions by blocking previous ones
	// Limit to prevent infinite loops
	maxSolutions := 100
	for len(allOptimalModels) < maxSolutions {
		// Create blocking clause: at least one UNKNOWN variable must differ from current model
		var blockingLits []maxsat.Lit
		for varName, val := range model {
			// Only block unknown edge variables, not all variables
			if !unknownVars[varName] {
				continue
			}
			lit := maxsat.Var(varName)
			if !val {
				lit = lit.Negation()
			}
			blockingLits = append(blockingLits, lit.Negation())
		}

		if len(blockingLits) == 0 {
			break // No unknown variables to block
		}

		// Add blocking clause as a hard constraint
		blockingConstr := maxsat.HardClause(blockingLits...)
		constraints = append(constraints, blockingConstr)

		// Create new problem with blocking clause
		prob := maxsat.New(constraints...)
		newModel, newCost := prob.Solve()

		// Stop if no more models or cost is worse
		if newModel == nil || newCost != optimalCost {
			break
		}

		allOptimalModels = append(allOptimalModels, newModel)
		model = newModel
	}

	return allOptimalModels
}

func modelsToSummaries(
	s *dataflow.State, allOptimalModels []maxsat.Model, unknown map[*dataflow.CallNode][]edge,
) (map[*ssa.Function][]summaries.DetailedSummary, error) {
	res := make(map[*ssa.Function][]summaries.DetailedSummary)
	for _, optimalModel := range allOptimalModels {
		// Extract may-flow edges from this model
		var allMayFlows []edge
		for _, edges := range unknown {
			for _, e := range edges {
				mayFlowVar := newMayFlowLit(e).Var
				if val, ok := optimalModel[mayFlowVar]; ok && val {
					allMayFlows = append(allMayFlows, e)
				}
			}
		}

		// Convert edges to summaries
		calleeToSumm, err := mayFlowEdgesToSummaries(allMayFlows)
		if err != nil {
			return res, fmt.Errorf("failed to convert edges to summaries: %v", err)
		}

		// Add empty summaries for callees with no inferred edges
		for call := range unknown {
			callee := call.Callee()
			if _, ok := calleeToSumm[callee]; !ok {
				// Create empty summary
				emptySumm := summaries.DetailedSummary{
					Flows: make(map[summaries.SummaryNode][]summaries.SummaryNode),
				}
				calleeToSumm[callee] = emptySumm
			}
		}

		for callee, summ := range calleeToSumm {
			cg, ok := s.FlowGraph.Summaries[callee]
			if !ok {
				return res, fmt.Errorf("no summary found for callee: %s", callee)
			}

			// Check if this summary already exists to avoid duplicates.
			// There may be duplicate summaries even for unique MaxSAT models because there may be
			// different variable (may-flow) assignments which map to the same summary.
			existing := res[cg.Parent]
			isDuplicate := false
			for _, existingSumm := range existing {
				if summariesEqual(summ, existingSumm) {
					isDuplicate = true
					break
				}
			}
			if isDuplicate {
				continue
			}

			res[cg.Parent] = append(res[cg.Parent], summ)
		}
	}

	return res, nil
}

// node represents a dataflow graph node, optionally scoped to a specific call site.
//
// The call site is important because if a function is called twice, then there needs to be two
// different nodes for each node in the callee: one for each call site.
type node struct {
	n    dataflow.GraphNode
	call *dataflow.CallNode
	path path
}

func (n node) String() string {
	pathStr := n.path.String()
	if n.call == nil {
		return graphNodeDesc(n.n) + pathStr
	}
	return fmt.Sprintf("%s_%s%s", graphNodeDesc(n.call), graphNodeDesc(n.n), pathStr)
}

// edge represents a inter or intra-procedural taint flow edge between two nodes.
// It can be hard or soft.
type edge struct {
	from    node
	to      node
	isSoft  bool
	isIntra bool
}

func newIntraHardEdge(from, to node) edge {
	return edge{from: from, to: to, isSoft: false, isIntra: true}
}

func newInterHardEdge(from, to node) edge {
	return edge{from: from, to: to, isSoft: false, isIntra: false}
}

func newIntraSoftEdge(from, to node) edge {
	return edge{from: from, to: to, isSoft: true, isIntra: true}
}

func (e edge) String() string {
	var hardness string
	if e.isSoft {
		hardness = "soft"
	} else {
		hardness = "hard"
	}
	var proc string
	if e.isIntra {
		proc = "intra"
	} else {
		proc = "inter"
	}
	return fmt.Sprintf("[%s][%s] %s->%s", proc, hardness, e.from.String(), e.to.String())
}

// newMayFlowLit creates a boolean variable representing the dataflow edge from→to.
func newMayFlowLit(e edge) maxsat.Lit {
	return maxsat.Var(fmt.Sprintf("%s->%s", e.from.String(), e.to.String()))
}

// mustNotFlowEdges returns edges representing the must-not-flows with access paths enumerated up to
// pathLen, where pathLen is the longest access path length in the flows.
func mustNotFlowEdges(mustNotFlows []flow, pathLen int) []edge {
	var edges []edge
	nodePathLen := make(map[dataflow.GraphNode]int)
	for _, mnf := range mustNotFlows {
		nodePathLen[mnf.from.node] = max(nodePathLen[mnf.from.node], mnf.from.path.len())
		nodePathLen[mnf.to.node] = max(nodePathLen[mnf.to.node], mnf.to.path.len())
		fromPaths := dataflow.AccessPathsOfType(mnf.from.node.Type(), pathLen)
		toPaths := dataflow.AccessPathsOfType(mnf.to.node.Type(), pathLen)
		fromPaths = append(fromPaths, "") // NOTE AccessPathsOfType is empty when pathLen == 0.
		toPaths = append(toPaths, "")
		for _, fromPath := range fromPaths {
			from := node{mnf.from.node, nil, newPath(fromPath, pathLen)}
			if !mnf.from.path.isCoveredBy(from.path) {
				continue
			}
			for _, toPath := range toPaths {
				to := node{mnf.to.node, nil, newPath(toPath, pathLen)}
				if from == to {
					continue
				}
				if !mnf.to.path.isCoveredBy(to.path) {
					continue
				}
				edg := newIntraHardEdge(from, to)
				if !slices.Contains(edges, edg) {
					edges = append(edges, edg)
				}
			}
		}
	}

	if pathLen > 0 {
		// Special case: if a node only appears field-insensitively in the must-not-flows, but the
		// summary is field-sensitive, make sure that its fields don't flow to each other.
		for n, pl := range nodePathLen {
			if pl == 0 {
				paths := dataflow.AccessPathsOfType(n.Type(), pathLen)
				for _, a := range paths {
					ap := newPath(a, pathLen)
					for _, b := range paths {
						bp := newPath(b, pathLen)
						if bp == ap || bp.isCoveredBy(ap) {
							// x -/-> x.f is a contradiction
							continue
						}
						from := node{n, nil, ap}
						to := node{n, nil, bp}
						edg := newIntraHardEdge(from, to)
						if !slices.Contains(edges, edg) {
							edges = append(edges, edg)
						}
					}
				}
			}
		}

	}

	return edges
}

// mayFlowEdgesToSummaries converts inferred edges to frontend dataflow summaries
func mayFlowEdgesToSummaries(unknown []edge) (map[*ssa.Function]summaries.DetailedSummary, error) {
	calleeFlows := make(map[*ssa.Function]summaries.DetailedSummary)
	for _, e := range unknown {
		if e.from.call != e.to.call {
			return nil, fmt.Errorf("invalid unknown may-flow edge: %+v", e)
		}

		callee := e.from.call.Callee()
		flows, ok := calleeFlows[callee]
		if !ok {
			flows = summaries.DetailedSummary{
				Flows: make(map[summaries.SummaryNode][]summaries.SummaryNode),
			}
		}

		// TODO Handle globals properly: skip for now.
		if _, ok := e.from.n.(*dataflow.AccessGlobalNode); ok {
			// return calleeFlows, fmt.Errorf("callee summary flow input %v is a global", e.from.n)
			continue
		}
		if _, ok := e.to.n.(*dataflow.AccessGlobalNode); ok {
			// return calleeFlows, fmt.Errorf("callee summary flow output %v is a global", e.to.n)
			continue
		}

		from := newSummaryNode(graphNode{e.from.n, e.from.path})
		to := newSummaryNode(graphNode{e.to.n, e.to.path})
		if slices.Contains(flows.Flows[from], to) {
			continue
		}
		flows.Flows[from] = append(flows.Flows[from], to)
		calleeFlows[callee] = flows
	}

	return calleeFlows, nil
}

// edgeSignature creates a semantic signature for an edge based on node types, indices, and paths.
// This allows matching edges across different call sites.
func edgeSignature(e edge) string {
	return fmt.Sprintf("%s->%s", nodeSignature(e.from), nodeSignature(e.to))
}

// nodeSignature creates a semantic signature for a node that is not specific to its enclosing
// (parent) function.
func nodeSignature(n node) string {
	var base string
	switch gn := n.n.(type) {
	case *dataflow.ParamNode:
		base = fmt.Sprintf("param:%d:%s", gn.Index(), gn.SsaNode().Name())
	case *dataflow.ReturnValNode:
		base = fmt.Sprintf("ret:%d", gn.Index())
	case *dataflow.FreeVarNode:
		base = fmt.Sprintf("fv:%s", gn.SsaNode().Name())
	case *dataflow.AccessGlobalNode:
		base = fmt.Sprintf("glob:%s", gn.Global.Value().Name())
	default:
		fmt.Println(fmt.Errorf("invalid summary node: %v", n.n))
	}
	return base + n.path.String()
}

// summariesEqual checks if two DetailedSummary instances are identical.
func summariesEqual(a, b summaries.DetailedSummary) bool {
	if len(a.Flows) != len(b.Flows) {
		return false
	}

	for fromNode, aTargets := range a.Flows {
		bTargets, ok := b.Flows[fromNode]
		if !ok || len(aTargets) != len(bTargets) {
			return false
		}

		// Check if all targets match (order doesn't matter)
		for _, aTarget := range aTargets {
			if !slices.Contains(bTargets, aTarget) {
				return false
			}
		}
	}

	return true
}

func isInputNode(n dataflow.GraphNode) bool {
	switch n.(type) {
	case *dataflow.ParamNode, *dataflow.FreeVarNode, *dataflow.AccessGlobalNode:
		return true
	default:
		return false
	}
}

func isOutputNode(n dataflow.GraphNode) bool {
	switch n.(type) {
	case *dataflow.ParamNode, *dataflow.FreeVarNode, *dataflow.ReturnValNode, *dataflow.AccessGlobalNode:
		return true
	default:
		return false
	}
}

// For debugging:

// func dbgConstrs(topic string, constrs []maxsat.Constr) {
// 	fmt.Println(topic)
// 	for _, c := range constrs {
// 		fmt.Printf("\t%v\n", c)
// 	}
// }

func dbgEdges(s *State, topic string, edges []edge) {
	s.Logger.Debugf("%s\n", topic)
	if len(edges) == 0 {
		s.Logger.Debugf("\t<none>\n")
		return
	}
	for _, e := range edges {
		s.Logger.Debugf("\t%+v\n", e.String())
	}
}
