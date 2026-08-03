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
)

// inferCalleeSummaries returns all the maximally-general (most data flow edges) callee summaries
// which satisfy the summary's must-not-flow requirements mustNotFlows.
// It also adds any potential sources of unsoundness to unsoundness.
//
// The returned calleeInference is the inference problem's own state, kept so that callers can later
// determine, for a given must-not-flow, whether it remains proven if only a subset of the returned
// callee summaries turn out to be sound (see unprovenFlowsAfterCalleeCheck).
func inferCalleeSummaries(
	ctx context.Context, s *State, g *dataflow.SummaryGraph,
	wantFlows []flow, mustNotFlows []flow,
	unsoundness *Unsoundness, via Method,
) (map[*ssa.Function][]summaries.DetailedSummary, *calleeInference, error) {
	if len(g.Callees) == 0 {
		s.Logger.Tracef("function %s is a leaf function (no callees)\n", g.Parent)
		return nil, nil, nil
	}

	if summaries.FnHasSummaries(g.Parent) {
		return nil, nil, fmt.Errorf(
			"should not be deducing callee summaries for pre-defined function: %v", g.Parent)
	}
	if pos := s.State.Program.Fset.Position(g.Parent.Pos()); analysisutil.IsStandardLibFilename(pos.Filename) {
		s.Logger.Warnf(
			"should not be deducing callee summaries for standard library function: %v", g.Parent)
	}

	validMethods := []Method{General, Types}
	if !slices.Contains(validMethods, via) {
		return nil, nil, fmt.Errorf("invalid inference method: want one of %v, got %v", validMethods, via)
	}

	// Compute the level of precision needed for the intra-procedural analysis.
	prec := newPrecisions(wantFlows)
	// Every node gets at least the precision of the most-precise node (the one with the longest
	// access path in wantFlows), so the intra-procedural analysis has enough depth to track any
	// field-sensitive flow the summary being checked cares about. This only sets nodePathLen (the
	// depth bound); prec.inputs.nodePaths/prec.outputs.nodePaths (the actual relevant paths from
	// wantFlows, used by inputNodes via relevantPathsOfType to avoid enumerating every leaf path
	// of nodes that have nothing relevant in them) are left untouched by this loop.
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
			if _, _, err := dataflow.RunIntraProcedural(ctx, s.State, g); err != nil {
				return nil, nil, fmt.Errorf(
					"failed to run field-insensitive intra-procedural analysis: %w", err)
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
			// TODO We want to use node-level precision eventually; but for now, just set the
			// precision of every node to the precision of the most-precise node (node with the
			// longest access path).
			if _, _, err := dataflow.RunIntraProceduralFields(ctx, s.State, g, k); err != nil {
				return nil, nil, fmt.Errorf(
					"failed to run field-sensitive intra-procedural analysis: %w", err)
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

	fg, err := buildGraph(ctx, s, g, prec, wantFlows, mustNotFlows)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build flow graph: %w", err)
	}
	graphEdges := fg.allEdges()
	if len(graphEdges) == 0 {
		return nil, nil, fmt.Errorf("no reachable flows from inputs")
	}
	s.Logger.Debugf(
		"taint flow graph has %d vertices and %d edges\n", len(fg.vertices), len(graphEdges))

	// unknownMayFlow are the edges that make up the callee taint flow summaries.
	unknownMayFlow := unknownMayFlowEdges(fg)

	if err := checkEncodingInvariants(fg, graphEdges); err != nil {
		return nil, nil, err
	}

	if s.Logger.LogsDebug() {
		flowEdges := make([]edge, 0, len(graphEdges))
		for _, ge := range graphEdges {
			flowEdges = append(flowEdges, fg.toEdge(ge))
		}
		dbgEdges(s, "flow graph edges:", flowEdges)
		for _, call := range sortedUnknownCalls(unknownMayFlow) {
			dbgEdges(
				s, "unknown summary edges for call "+call.CallSite().String()+":",
				unknownMayFlow[call])
		}
	}

	// Build MaxSAT problem
	s.Logger.Debugf("computing problem constraints...")
	var constraints []maxsat.Constr
	// Callees of the same function must have identical inferred summaries, known (hard) edges are
	// asserted true, and reachability constraints propagate flows through the graph. These are
	// exactly the "base" constraints reused by unprovenFlowsAfterCalleeCheck to re-check
	// individual must-not-flows once some callees turn out unsound.
	// TODO This assumes that all nodes have the same precision.
	baseConstrs, err := calleeGraphConstraints(ctx, fg)
	if err != nil {
		return nil, nil, err
	}
	constraints = append(constraints, baseConstrs...)
	s.Logger.Debugf("\t%d hard constraints for identical callee summaries/known edges/reachability",
		len(baseConstrs))

	// Maximize unknown may-flow edges (minimize must-not-flow).
	softConstrs := buildSoftConstraints(unknownMayFlow)
	constraints = append(constraints, softConstrs...)
	s.Logger.Debugf("\t%d soft constraints for callee's may-flow edges", len(softConstrs))

	// Block must-not-flows
	mustNotFlowConstrs, err := buildMustNotFlowConstraints(ctx, fg, mustNotFlows, prec.longestPathLen > 0)
	if err != nil {
		return nil, nil, err
	}
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
		return nil, nil, nil
	}

	// Enumerate all optimal models and convert them to summaries
	allOptimalModels, err := findAllOptimalModels(ctx, model, optimalCost, constraints, unknownMayFlow)
	if err != nil {
		return nil, nil, err
	}
	res, err := modelsToSummaries(s.State, allOptimalModels, unknownMayFlow)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert maxsat model to summaries: %v", err)
	}

	s.Logger.Debugf(
		"callee summary inference for function %s took %s\n", g.Parent, time.Since(start))

	for callee, summs := range res {
		s.Logger.Debugf("inferred summaries for callee %s:\n", callee)
		for _, summ := range summs {
			s.Logger.Debugf("\t%s\n", summ)
		}
	}

	return res, &calleeInference{fg: fg, models: allOptimalModels}, nil
}

// checkCancelled reports ctx's error, labelled with the phase that was running.
//
// Inference has no natural yield points once the intra-procedural analysis is done, so the phases that
// scale with graph size poll this. The maxsat solver cannot be interrupted, so a single long Solve call
// overshoots the deadline regardless.
func checkCancelled(ctx context.Context, phase string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", phase, err)
	}
	return nil
}

// calleeInference is the state of one callee summary inference problem, beyond the summaries it
// produced: the flow graph the problem was built over, and every optimal model the solver found.
//
// unprovenFlowsAfterCalleeCheck re-examines the same problem once some callees turn out unsound, so
// it needs both -- the graph to search for a surviving route, and the models to know which callee
// edges the inference had concluded were absent.
type calleeInference struct {
	fg     *flowGraph
	models []maxsat.Model
}

// setsAnyTrue reports whether any of the models assigned the variable v true.
func (ci *calleeInference) setsAnyTrue(v string) bool {
	for _, m := range ci.models {
		if m[v] {
			return true
		}
	}
	return false
}

// unprovenFlowsAfterCalleeCheck returns the subset of mustNotFlows that remain unproven after
// recursively checking the soundness of the callee summaries inferred by inferCalleeSummaries.
//
// inferCalleeSummaries blocks every flow in mustNotFlows *assuming its inferred summaries are
// correct*. Once a callee's summary turns out unsound, the soft edges that summary claimed were
// absent can no longer be trusted, so each must-not-flow is re-checked over the edges we still
// believe may exist: if its input can still reach its output, it stays unproven.
//
// unsoundCalleeFlows maps each unsound callee to its own reported UnprovenMustNotFlows. Only the
// edges for those specific flows are re-opened, not every edge of the callee: edges independently
// disproven while checking the callee are genuinely absent and must stay blocked. See
// realizableCalleeEdges.
//
// This is a graph search instead of a SAT query because the assignment is no longer being chosen.
// maxsat cannot answer it: reachability is encoded as implications that only force reach upward, so
// asserting a reach variable is satisfiable with no supporting path, and every must-not-flow whose
// endpoints appear in the graph would come back unproven.
func unprovenFlowsAfterCalleeCheck(
	ctx context.Context, s *State, g *dataflow.SummaryGraph, wantFlows, mustNotFlows []flow,
	inf *calleeInference, unsoundCalleeFlows map[*ssa.Function][]Flow,
) ([]flow, error) {
	if len(unsoundCalleeFlows) == 0 {
		// No unsound callees: every must-not-flow that inferCalleeSummaries was able to block is
		// validly proven.
		return nil, nil
	}
	if len(inf.fg.allEdges()) == 0 {
		// An empty graph means nothing was proven via callee inference; keep everything.
		return mustNotFlows, nil
	}
	prec := newPrecisions(wantFlows)
	g.ForAllNodes(func(n dataflow.GraphNode) {
		prec.inputs.nodePathLen[n] = prec.longestPathLen
		prec.outputs.nodePathLen[n] = prec.longestPathLen
	})

	unknownMayFlow := unknownMayFlowEdges(inf.fg)
	reopened, err := edgesForUnsoundCalleeFlows(s, unknownMayFlow, unsoundCalleeFlows)
	if err != nil {
		return nil, err
	}
	admit := realizableCalleeEdges(inf, unknownMayFlow, reopened)

	var stillUnproven []flow
	for _, mnf := range mustNotFlows {
		// Each must-not-flow is searched for on its own, rather than all of them at once, because
		// each needs its own independent proven/unproven verdict.
		realizable, err := mustNotFlowIsRealizable(ctx, inf.fg, mnf, admit)
		if err != nil {
			return nil, err
		}
		if realizable {
			stillUnproven = append(stillUnproven, mnf)
		}
	}
	return stillUnproven, nil
}

// realizableCalleeEdges returns the predicate deciding which flow graph edges the callee re-check
// may travel over: every known (hard) edge, plus each callee summary edge that either one of the
// inference's optimal models claimed or reopened puts back in doubt.
//
// A summary edge outside both sets is one the inference concluded was absent and that checking the
// callee did not call into question, so no route may use it. Admitting those too is what made the
// re-check degenerate into "are these endpoints connected in the graph at all", which holds far more
// often than the must-not-flow is realizable.
//
// That reasoning needs the model enumeration to have been exhaustive. If it hit its cap, an edge no
// enumerated model claimed may still be claimed by a co-optimal model we never saw, so every summary
// edge is admitted instead: truncating the enumeration then costs precision, never soundness.
//
// A soft edge that is not a summary edge at all (so never became a maxsat variable) is admitted, so
// that the models' silence about it is not read as a disproof.
func realizableCalleeEdges(
	inf *calleeInference, unknownMayFlow map[*dataflow.CallNode][]edge, reopened []edge,
) func(gedge) bool {
	if !modelsAreComplete(inf.models) {
		return func(gedge) bool { return true }
	}

	isSummaryEdge := make(map[string]struct{})
	for _, e := range sortedUnknownEdges(unknownMayFlow) {
		isSummaryEdge[newMayFlowLit(e).Var] = struct{}{}
	}
	inDoubt := make(map[string]struct{}, len(reopened))
	for _, e := range reopened {
		inDoubt[newMayFlowLit(e).Var] = struct{}{}
	}

	return func(ge gedge) bool {
		if !ge.isSoft {
			return true
		}
		v := newMayFlowLit(inf.fg.toEdge(ge)).Var
		if _, ok := isSummaryEdge[v]; !ok {
			return true
		}
		if _, ok := inDoubt[v]; ok {
			return true
		}
		return inf.setsAnyTrue(v)
	}
}

// mustNotFlowIsRealizable reports whether some input matching one of mnfEdges' sources can still
// reach an output matching that edge's target, travelling only over edges admit accepts.
func mustNotFlowIsRealizable(
	ctx context.Context, fg *flowGraph, mnf flow, admit func(gedge) bool,
) (bool, error) {
	for _, src := range fg.seeds {
		if err := checkCancelled(ctx, "must-not-flow re-check"); err != nil {
			return false, err
		}
		if src.node != mnf.from.node || !pathsOverlap(src.path, mnf.from.path) {
			continue
		}
		for _, v := range reachableFromVia(fg, src, admit) {
			if v.key() == src.key() {
				continue
			}
			if v.node == mnf.to.node && pathsOverlap(v.path, mnf.to.path) {
				return true, nil
			}
		}
	}
	return false, nil
}

// edgesForUnsoundCalleeFlows resolves each unsound callee's reported UnprovenMustNotFlows (given in
// that callee's own signature vocabulary) against the caller's unknownMayFlow edges, returning the
// specific edges (across every call site to that callee) that correspond to those flows.
//
// Resolution must happen per call site, against that call site's own call.CalleeSummary graph, not
// against s.FlowGraph.Summaries[callee]: checkCalleeSummaries recursively calls checkSummary on the
// callee to verify its inferred summary, and checkSummary unconditionally builds a brand-new
// dataflow.SummaryGraph for the function it's given, overwriting s.FlowGraph.Summaries[callee] with
// a graph whose nodes are distinct (pointer-wise) from the ones the flow graph/unknownMayFlow were
// built with -- so resolving there would silently match nothing.
func edgesForUnsoundCalleeFlows(
	s *State, unknownMayFlow map[*dataflow.CallNode][]edge, unsoundCalleeFlows map[*ssa.Function][]Flow,
) ([]edge, error) {
	var forced []edge
	for _, call := range sortedUnknownCalls(unknownMayFlow) {
		edges := unknownMayFlow[call]
		flows, ok := unsoundCalleeFlows[call.Callee()]
		if !ok {
			continue
		}
		var calleeFlows []flow
		for _, f := range flows {
			fl, err := flowFromReport(call.CalleeSummary, f)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to resolve unproven flow %v for callee %s: %v", f, call.Callee(), err)
			}
			calleeFlows = append(calleeFlows, fl)
		}
		for _, fl := range calleeFlows {
			matched := 0
			for _, e := range edges {
				if matchesReportedFlow(e, fl) {
					forced = append(forced, e)
					matched++
				}
			}
			if matched == 0 {
				// Not fatal, but worth surfacing: the re-check treats a summary edge no model
				// claimed as disproven, so an unsound callee's flow that resolves to no edge is
				// silently dropped from the worst case and a must-not-flow it realizes can come back
				// proven. The likely cause is resolving against the wrong graph -- checkSummary
				// rebuilds s.FlowGraph.Summaries[callee] with fresh nodes, which is why resolution
				// goes through each call site's own call.CalleeSummary.
				s.Logger.Warnf(
					"unproven flow %v of unsound callee %s matched no may-flow edge at call site %v;"+
						" it will not be treated as realizable\n",
					fl, call.Callee(), call.CallSite())
			}
		}
	}
	return forced, nil
}

// matchesReportedFlow reports whether the graph edge e realizes the callee flow fl, which was
// reported by the callee's own check.
//
// The two are stated at different granularities and neither side is consistently coarser: fl is in
// the callee's summary vocabulary, which may name a return value as a whole, while
// calleeOutputDemand gives the graph edges whatever depth the callers read them at. So the
// endpoints must match by position with overlapping paths, not by equality. Over-matching here only
// widens the worst case.
func matchesReportedFlow(e edge, fl flow) bool {
	return e.from.node == fl.from.node && e.to.node == fl.to.node &&
		pathsOverlap(e.from.path, fl.from.path) && pathsOverlap(e.to.path, fl.to.path)
}

// flowFromReport converts a reported Flow (the exported, summary-node based representation used in
// SoundnessResult) back into the internal graph-node based flow representation, resolving both
// endpoints against g. This is the inverse of newFlow, used by edgesForUnsoundCalleeFlows to
// translate a callee's own reported UnprovenMustNotFlows back into edges over the caller's view of
// that callee's graph nodes.
func flowFromReport(g *dataflow.SummaryGraph, f Flow) (flow, error) {
	from, err := findNode(g, f.From)
	if from == nil || err != nil {
		return flow{}, fmt.Errorf("could not find node for %v: %v", f.From, err)
	}
	to, err := findNode(g, f.To)
	if to == nil || err != nil {
		return flow{}, fmt.Errorf("could not find node for %v: %v", f.To, err)
	}
	return flow{
		from: newSummaryNode(from, f.From.Path()),
		to:   newSummaryNode(to, f.To.Path()),
	}, nil
}

// buildGraph builds the taint flow graph of g, tainting every input at the access path length prec
// specifies.
//
// Construction is a monotone worklist fixpoint over vertices.
//
// Access-path precision is per node:
//   - The parent's own nodes use the precision its intra-procedural analysis computed.
//   - Summary endpoints are seeded at that summary's path length (inputNodes)
//   - A callee's outputs get only the access path depth the caller is observed to read them at
//     (calleeOutputPaths)
//
// coarsen then collapses whatever precision turned out to be unobservable.
func buildGraph(
	ctx context.Context, s *State, g *dataflow.SummaryGraph,
	prec *precisions, wantFlows, mustNotFlows []flow,
) (*flowGraph, error) {
	fg := newFlowGraph()
	fg.outputPaths = calleeOutputDemand(g)
	for _, input := range inputNodes(g, prec) {
		seed := newVertex(
			input.Node, newPath(input.AccessPaths[0], maxPathLen),
			nil, input.Status, nil)
		if err := buildFlowGraph(ctx, s, fg, seed); err != nil {
			// Cancellation will recur for every remaining input, so abort instead of skipping.
			if ctx.Err() != nil {
				return nil, err
			}
			s.Logger.Errorf("failed to build flow graph for input %v: %v", input, err)
			continue
		}
		fg.seeds = append(fg.seeds, seed)
	}

	// Run the coarsening step: after every input has been expanded (so no distinction can still be
	// discovered) and before handing the graph to the maxsat encoding.
	n, err := coarsen(fg, distinguishedPathLens(wantFlows, mustNotFlows))
	if err != nil {
		return nil, err
	}
	if n > 0 {
		s.Logger.Debugf("coarsened %d indistinguishable flow graph vertices\n", n)
	}

	// The callee input vocabulary is fixed last, over the final graph, since coarsening can still
	// change which paths its vertices carry.
	fg.inputPaths = calleeInputDemand(fg)

	return fg, nil
}

// distinguishedPathLens returns, per graph node, the deepest access path at which the maxsat
// encoding refers to that node: the endpoints of the summary being checked and of its
// must-not-flows. A node absent from the result is only ever referred to as a whole, so nothing can
// tell its fields apart. See coarsen.
func distinguishedPathLens(flowSets ...[]flow) map[dataflow.GraphNode]int {
	lens := make(map[dataflow.GraphNode]int)
	for _, flows := range flowSets {
		for _, fl := range flows {
			lens[fl.from.node] = max(lens[fl.from.node], fl.from.path.len())
			lens[fl.to.node] = max(lens[fl.to.node], fl.to.path.len())
		}
	}
	return lens
}

// nodeSsaValue returns the ssa.Value underlying node, if node is a kind of node whose identity is
// tied to a single ssa.Value (currently: ParamNode and CallNodeArg). It returns nil for any other
// node kind.
func nodeSsaValue(node dataflow.GraphNode) ssa.Value {
	switch n := node.(type) {
	case *dataflow.ParamNode:
		return n.SsaNode()
	case *dataflow.CallNodeArg:
		return n.Value()
	default:
		return nil
	}
}

// isRedundantIntraSelfFlow reports whether the intra-procedural edge from src (at curPath) to
// dst (at nextPath) is a redundant self-flow introduced by passing a value as-is into a call,
// e.g. f(r) where r is src's own ssa.Value: dst is then a CallNodeArg wrapping that same
// ssa.Value. Passing r into the call at the same access path (curPath == nextPath) is the
// legitimate way to enter the callee's analysis for that field and must not be filtered. But when
// nextPath is strictly deeper than curPath (a proper extension, e.g. curPath is r.safeBody and
// nextPath is r.safeBody.closed), the edge doesn't correspond to any real flow discovered by the
// intra-procedural analysis of the callee: it's an artifact of curPath itself already being a
// collapsed, field-insensitive placeholder for "any field of r.safeBody" (see
// relevantPathsOfType/allCalleeOutputs), and following it would force every field of that
// collapsed subtree to be re-expanded one level deeper at every call site the value passes
// through.
func isRedundantIntraSelfFlow(src, dst dataflow.GraphNode, curPath, nextPath path) bool {
	if curPath == nextPath {
		return false
	}
	srcVal := nodeSsaValue(src)
	dstVal := nodeSsaValue(dst)
	if srcVal == nil || dstVal == nil || srcVal != dstVal {
		return false
	}
	// Only filter when nextPath is a proper extension of curPath (strictly deeper, same prefix).
	// curPath.isCoveredBy(nextPath) means curPath is a prefix of nextPath (or equal); we want the
	// opposite direction (nextPath strictly deeper), which the curPath == nextPath check above
	// already excludes the equal case for.
	return curPath.isCoveredBy(nextPath) && curPath.len() < nextPath.len()
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
	curPathParsed := newPath(curPath, maxPathLen)

	if len(edgeInfo.RelPath) == 0 {
		// If there's no edge information, this is likely an inter-procedural flow or a callee
		// intra-procedural flow. Enumerate all the possible access paths with a maximum length of
		// of the current access path.
		//
		// HACK newPath is the easiest way to compute the access path length for now since the
		// dataflow analysis processes them as strings.
		curLen := curPathParsed.len()
		edgeInfo.RelPath = make(map[string]map[string]bool)
		edgeInfo.RelPath[curPath] = make(map[string]bool)
		if cur.Node.Graph() == next.Node.Graph() {
			// If this is an intra-procedural flow, then enumerate all the possible outgoing access
			// paths.
			for _, nextPath := range leafPathsUpTo(next.Node.Type(), curLen) {
				if isRedundantIntraSelfFlow(cur.Node, next.Node, curPathParsed, nextPath) {
					continue
				}
				edgeInfo.RelPath[curPath][nextPath.String()] = true
			}
		} else {
			// If this is an inter-procedural flow, then the outgoing access path is the incoming
			// access path.
			edgeInfo.RelPath[curPath][curPath] = true
		}
	}

	for inPath, outPaths := range edgeInfo.RelPath {
		if !curPathParsed.isCoveredBy(newPath(inPath, maxPathLen)) {
			continue
		}
		for outPath := range outPaths {
			if cur.Node.Graph() == next.Node.Graph() {
				nextPathParsed := newPath(outPath, maxPathLen)
				if isRedundantIntraSelfFlow(cur.Node, next.Node, curPathParsed, nextPathParsed) {
					continue
				}
			}
			nextPaths = append(nextPaths, outPath)
		}
	}

	return nextPaths
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
			// prec.inputs.nodePaths[n] holds the real access paths (from the original wantFlows,
			// not the uniform pl assigned above) that are actually relevant for n; paths outside
			// them collapse to a single entry per branch instead of being enumerated leaf-by-leaf
			// (see relevantPathsOfType). This is what turns buildGraph's per-leaf-path DFS fan-out
			// (one full traversal per leaf path of n's type) into one DFS per relevant leaf path
			// plus a small, fixed number of collapsed-branch DFS runs, instead of one per every
			// leaf path the type happens to have.
			paths := relevantPathsOfType(n.Type(), pl, prec.inputs.nodePaths[n])
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

	// g.ForAllNodes walks a map, so the inputs come out in random order. That order determines the
	// order the flow graph is expanded in, and therefore the order its edges and reachability
	// clauses are emitted in.
	slices.SortFunc(inputs, func(a, b *dataflow.VisitorNode) int {
		if c := strings.Compare(graphNodeDesc(a.Node), graphNodeDesc(b.Node)); c != 0 {
			return c
		}
		return strings.Compare(a.AccessPaths[0], b.AccessPaths[0])
	})

	return inputs
}

// unknownMayFlowEdges collects the intra-procedural soft (unknown) edges belonging to each callee
// -- i.e. the edges that make up the callee taint flow summaries to be inferred, or (for
// unprovenFlowsAfterCalleeCheck) re-examined.
//
// Every soft edge construction discovered is a genuine may-flow hypothesis and must become a maxsat
// variable.
func unknownMayFlowEdges(fg *flowGraph) map[*dataflow.CallNode][]edge {
	unknownMayFlow := make(map[*dataflow.CallNode][]edge)
	for _, ge := range fg.allEdges() {
		edg := fg.toEdge(ge)
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
	return unknownMayFlow
}

// checkEncodingInvariants verifies the two naming invariants the maxsat encoding depends on, and
// returns an error if either is violated.
//
// Both failures are silent corruptions of the problem rather than crashes -- they make the solver
// answer a different question than the one intended -- so they are checked on every run rather than
// left to tests, and reported as errors rather than logged: a wrong soundness verdict is worse than
// no verdict.
func checkEncodingInvariants(fg *flowGraph, edges []gedge) error {
	if err := checkVarNameUniqueness(fg, edges); err != nil {
		return err
	}
	return checkCalleeVocabulary(fg, edges)
}

// checkVarNameUniqueness reports any two structurally distinct edges that would share a maxsat
// variable name.
//
// It only considers edges that are not callee summary edges. Summary edges share a name *by design*
// -- that is what calleeFlowKey is for, since the same summary fact observed at two call sites is one
// variable. For every other edge the name comes from calledSummaryNode.varID, built on
// GraphNode.LongID, and uniqueness is the invariant. A collision conflates two independent facts:
// before varID existed, names came from rendered SSA text and 22 collided across this test suite
// alone.
func checkVarNameUniqueness(fg *flowGraph, edges []gedge) error {
	byName := make(map[string]string, len(edges))
	for _, ge := range edges {
		e := fg.toEdge(ge)
		if _, isSummary := calleeFlowKeyOf(e); isSummary {
			continue
		}
		name := newMayFlowLit(e).Var
		desc := e.String()
		if prev, ok := byName[name]; ok && prev != desc {
			return fmt.Errorf(
				"maxsat variable name collision: %q is shared by %s and %s, which would conflate the two flows",
				name, prev, desc)
		}
		byName[name] = desc
	}
	return nil
}

// checkCalleeVocabulary checks that each position in a callee's inferred summary is named at a single
// access path granularity.
//
// A callee's summary is one set of facts shared by every call site targeting it, and calleeFlowKey
// names a summary edge partly by its access path. If the same position is named both bare and at a
// field, those are two unrelated maxsat variables: the solver assigns them independently and the
// reported summary is the union of both, which is more general than any single call site's model
// justified. calleeOutputDemand and calleeInputDemand exist to prevent that, from the output and
// input sides respectively.
//
// The check is stated over the summary vocabulary rather than over what those two functions compute,
// so it fails if either stops covering a case rather than merely restating what they do. Two distinct
// paths for one position are fine only if neither is a prefix of the other: .First and .Second are
// separate facts, whereas "" and .First are the same fact at two granularities.
func checkCalleeVocabulary(fg *flowGraph, edges []gedge) error {
	type position struct {
		callee *ssa.Function
		node   summaries.SummaryNode
		isFrom bool
	}
	paths := make(map[position][]path)
	record := func(callee *ssa.Function, sn summaries.SummaryNode, isFrom bool) {
		pos := position{callee: callee, node: sn.WithObjectPath(""), isFrom: isFrom}
		p := newPath(sn.Path(), maxPathLen)
		if !slices.Contains(paths[pos], p) {
			paths[pos] = append(paths[pos], p)
		}
	}
	for _, ge := range edges {
		k, ok := calleeFlowKeyOf(fg.toEdge(ge))
		if !ok {
			continue
		}
		record(k.callee, k.from, true)
		record(k.callee, k.to, false)
	}

	for pos, ps := range paths {
		for i, a := range ps {
			for _, b := range ps[i+1:] {
				if !pathsOverlap(a, b) {
					continue
				}
				side := "output"
				if pos.isFrom {
					side = "input"
				}
				return fmt.Errorf(
					"callee %s %s %v is named at two access path granularities, %q and %q:"+
						" they become independent maxsat variables, so the inferred summary would be"+
						" the union of both",
					pos.callee.String(), side, pos.node, a.String(), b.String())
			}
		}
	}
	return nil
}

// calleeGraphConstraints returns the structural constraints of the inference problem: callees called
// at multiple sites must have identical inferred summaries, known (hard) edges are asserted true, and
// reachability propagates flows through the graph. inferCalleeSummaries adds the soft
// (maximization) and must-not-flow (blocking) constraints on top.
func calleeGraphConstraints(ctx context.Context, fg *flowGraph) ([]maxsat.Constr, error) {
	reach, err := buildReachabilityConstraints(ctx, fg)
	if err != nil {
		return nil, err
	}
	var constrs []maxsat.Constr
	constrs = append(constrs, buildHardConstraints(fg)...)
	constrs = append(constrs, reach...)
	return constrs, nil
}

// buildSoftConstraints returns the constraints to maximize the soft (unknown) edges.
func buildSoftConstraints(unknownMayFlow map[*dataflow.CallNode][]edge) []maxsat.Constr {
	var maxConstrs []maxsat.Constr
	// Deterministically ordered: the soft clauses are what the solver optimizes over, so their
	// order decides which of several equally-optimal models it reports first.
	for _, e := range sortedUnknownEdges(unknownMayFlow) {
		maxConstrs = append(maxConstrs, maxsat.SoftClause(newMayFlowLit(e)))
	}
	return maxConstrs
}

// buildHardConstraints asserts every known (hard) edge of the flow graph true.
func buildHardConstraints(fg *flowGraph) []maxsat.Constr {
	var constraints []maxsat.Constr
	seen := make(map[string]struct{})
	for _, ge := range fg.allEdges() {
		if ge.isSoft {
			continue
		}
		lit := newMayFlowLit(fg.toEdge(ge))
		if _, ok := seen[lit.Var]; ok {
			continue
		}
		seen[lit.Var] = struct{}{}
		constraints = append(constraints, maxsat.HardClause(lit))
	}
	return constraints
}

// reachLit is the variable meaning "vertex v is reachable from the input src along edges that the
// model assigns true".
func reachLit(src, v vertex) maxsat.Lit {
	return maxsat.Var(fmt.Sprintf("reach[%s=>%s]", vertexID(src), vertexID(v)))
}

// buildReachabilityConstraints encodes the flow graph's reachability relation directly.
//
// For every input src, reach(src, src) is asserted, and every edge u->v reachable from src
// contributes
//
//	¬reach(src,u) ∨ ¬edge(u,v) ∨ reach(src,v)
//
// so an assignment of the callee summary (soft) edges forces reach(src,v) true exactly when some
// path of true edges connects them. reach occurs positively only as the head of these implications,
// so the solver may leave it false wherever nothing forces it -- which is what makes ¬reach usable
// to block a must-not-flow.
//
// Linear in (inputs x edges), and covers every path at once. The previous scheme flattened the graph
// into root-to-output paths and emitted one transitivity clause per path, which to stay polynomial had
// to pick one prefix and one suffix per edge based on traversal order -- so the constraint set was not
// a function of the graph, and two runs could disagree about whether a must-not-flow was provable.
func buildReachabilityConstraints(ctx context.Context, fg *flowGraph) ([]maxsat.Constr, error) {
	var constrs []maxsat.Constr
	for _, src := range fg.seeds {
		if err := checkCancelled(ctx, "reachability encoding"); err != nil {
			return nil, err
		}
		constrs = append(constrs, maxsat.HardClause(reachLit(src, src)))
		for _, v := range reachableFrom(fg, src) {
			for _, e := range fg.out[v.key()] {
				constrs = append(constrs, maxsat.HardClause(
					reachLit(src, e.from).Negation(),
					newMayFlowLit(fg.toEdge(e)).Negation(),
					reachLit(src, e.to)))
			}
		}
	}
	return constrs, nil
}

// mustNotFlowReachability returns the reachability variables that realize some must-not-flow: one per
// (input, reachable vertex) pair whose endpoints match one. buildMustNotFlowConstraints negates these
// to block the flows.
//
// Endpoints match on overlapping paths rather than on prefix in one direction, because neither side
// is consistently coarser: a must-not-flow may name .Second while the graph only has a vertex for
// the whole value, or name the whole value while the graph is field-sensitive. Both mean the vertex
// holds memory the must-not-flow is about.
//
// fieldSensitive additionally blocks flows between distinct fields of a node that the must-not-flows
// only ever name as a whole. Without it, a field-sensitive summary that says nothing about a node's
// fields would let one field reach another and be used as a stepping stone.
func mustNotFlowReachability(
	ctx context.Context, fg *flowGraph, mustNotFlows []flow, fieldSensitive bool,
) ([]maxsat.Lit, error) {
	// Nodes the must-not-flows name without any access path.
	namedAsWhole := make(map[dataflow.GraphNode]bool)
	for _, mnf := range mustNotFlows {
		for _, end := range []summaryNode{mnf.from, mnf.to} {
			if end.path.len() == 0 {
				namedAsWhole[end.node] = true
			}
		}
	}

	var lits []maxsat.Lit
	seen := make(map[string]struct{})
	add := func(src, v vertex) {
		if v.key() == src.key() {
			return
		}
		lit := reachLit(src, v)
		if _, ok := seen[lit.Var]; ok {
			return
		}
		seen[lit.Var] = struct{}{}
		lits = append(lits, lit)
	}

	for _, src := range fg.seeds {
		if err := checkCancelled(ctx, "must-not-flow encoding"); err != nil {
			return nil, err
		}
		reachable := reachableFrom(fg, src)
		for _, mnf := range mustNotFlows {
			if src.node != mnf.from.node || !pathsOverlap(src.path, mnf.from.path) {
				continue
			}
			for _, v := range reachable {
				if v.node != mnf.to.node || !pathsOverlap(v.path, mnf.to.path) {
					continue
				}
				add(src, v)
			}
		}

		if !fieldSensitive || !namedAsWhole[src.node] {
			continue
		}
		for _, v := range reachable {
			// x -/-> x.f is a contradiction, so only distinct, non-nested fields are blocked.
			if v.node != src.node || v.path.isCoveredBy(src.path) {
				continue
			}
			add(src, v)
		}
	}
	return lits, nil
}

// buildMustNotFlowConstraints returns the constraints that block must-not-flows: no input may reach
// an output the summary says it must not reach.
func buildMustNotFlowConstraints(
	ctx context.Context, fg *flowGraph, mustNotFlows []flow, fieldSensitive bool,
) ([]maxsat.Constr, error) {
	lits, err := mustNotFlowReachability(ctx, fg, mustNotFlows, fieldSensitive)
	if err != nil {
		return nil, err
	}
	var constrs []maxsat.Constr
	for _, lit := range lits {
		constrs = append(constrs, maxsat.HardClause(lit.Negation()))
	}
	return constrs, nil
}

// sortedUnknownEdges flattens unknown into a single deterministically ordered slice.
//
// unknown is keyed by *dataflow.CallNode, so iterating it directly yields a different order on
// every run. That order leaks into results in two ways: findAllOptimalModels builds its blocking
// clause from it (so which co-optimal models get discovered before hitting the solution limit
// varies), and modelsToSummaries accumulates may-flow edges from it. Both then change which
// callee summaries are reported for a function with several equally-optimal summaries (e.g. a
// symmetric callee like `addVals(a, b)`, where `a -> {b, ret}` and `b -> {a, ret}` satisfy the
// same number of may-flow edges).
func sortedUnknownEdges(unknown map[*dataflow.CallNode][]edge) []edge {
	var edges []edge
	for _, es := range unknown {
		edges = append(edges, es...)
	}
	// Ordered by the human-readable form, with the unique variable id only as a tiebreak. Sorting by
	// the variable id alone would make the order depend on GraphNode.LongID's summary-graph counter,
	// so an unrelated change in how many summaries get built before this one would silently reshuffle
	// which co-optimal model the solver reports. The display form is independent of that, and the
	// tiebreak keeps the comparison total even where two nodes render identically.
	slices.SortFunc(edges, func(a, b edge) int {
		if c := strings.Compare(a.String(), b.String()); c != 0 {
			return c
		}
		return strings.Compare(newMayFlowLit(a).Var, newMayFlowLit(b).Var)
	})
	return edges
}

// sortedUnknownCalls returns unknown's call sites in a deterministic order, for the same reason
// sortedUnknownEdges exists.
func sortedUnknownCalls(unknown map[*dataflow.CallNode][]edge) []*dataflow.CallNode {
	calls := make([]*dataflow.CallNode, 0, len(unknown))
	for call := range unknown {
		calls = append(calls, call)
	}
	slices.SortFunc(calls, func(a, b *dataflow.CallNode) int {
		return strings.Compare(a.LongID(), b.LongID())
	})
	return calls
}

// maxOptimalModels bounds how many co-optimal models findAllOptimalModels enumerates. Truncating
// what gets reported is acceptable; see modelsAreComplete for the one place the distinction matters.
const maxOptimalModels = 100

func findAllOptimalModels(
	ctx context.Context, model maxsat.Model, optimalCost int, constraints []maxsat.Constr,
	unknown map[*dataflow.CallNode][]edge,
) ([]maxsat.Model, error) {
	// The unknown edge variables, in a deterministic order: these are the only ones blocked (the
	// hard-edge variables are fixed anyway), and the order they appear in each blocking clause
	// steers the solver's search, so iterating the model map here would make which co-optimal
	// models get enumerated -- and how many -- vary between runs.
	var unknownVars []string
	seenVar := make(map[string]bool)
	for _, e := range sortedUnknownEdges(unknown) {
		v := newMayFlowLit(e).Var
		if seenVar[v] {
			continue
		}
		seenVar[v] = true
		unknownVars = append(unknownVars, v)
	}

	// Collect all models with the optimal cost
	allOptimalModels := []maxsat.Model{model}
	// Enumerate all other optimal solutions by blocking previous ones
	// Create blocking clause: at least one UNKNOWN variable must differ from current model
	for len(allOptimalModels) < maxOptimalModels {
		// Abort rather than returning the models found so far: modelsAreComplete infers truncation from
		// having hit maxOptimalModels, so a short enumeration would claim to be complete and every
		// unenumerated summary edge would be treated as disproven.
		if err := checkCancelled(ctx, "model enumeration"); err != nil {
			return nil, err
		}
		var blockingLits []maxsat.Lit
		for _, varName := range unknownVars {
			val, ok := model[varName]
			if !ok {
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

	return allOptimalModels, nil
}

// modelsAreComplete reports whether findAllOptimalModels enumerated every optimal model rather than
// stopping at its cap.
//
// It matters because unprovenFlowsAfterCalleeCheck treats a callee summary edge that no enumerated
// model claimed as disproven. That inference is only valid if the enumeration was exhaustive: a
// dropped co-optimal model's edges would be wrongly ruled out, and a must-not-flow that model
// realizes would be reported proven. See realizableCalleeEdges, which falls back to admitting
// everything when the set is incomplete.
func modelsAreComplete(models []maxsat.Model) bool {
	return len(models) < maxOptimalModels
}

func modelsToSummaries(
	s *dataflow.State, allOptimalModels []maxsat.Model, unknown map[*dataflow.CallNode][]edge,
) (map[*ssa.Function][]summaries.DetailedSummary, error) {
	res := make(map[*ssa.Function][]summaries.DetailedSummary)
	for _, optimalModel := range allOptimalModels {
		// Extract may-flow edges from this model
		var allMayFlows []edge
		for _, e := range sortedUnknownEdges(unknown) {
			mayFlowVar := newMayFlowLit(e).Var
			if val, ok := optimalModel[mayFlowVar]; ok && val {
				allMayFlows = append(allMayFlows, e)
			}
		}

		// Convert edges to summaries
		calleeToSumm, err := mayFlowEdgesToSummaries(allMayFlows)
		if err != nil {
			return res, fmt.Errorf("failed to convert edges to summaries: %v", err)
		}

		// Add empty summaries for callees with no inferred edges
		for _, call := range sortedUnknownCalls(unknown) {
			callee := call.Callee()
			if _, ok := calleeToSumm[callee]; !ok {
				// Create empty summary
				emptySumm := summaries.DetailedSummary{
					Flows: make(map[summaries.SummaryNode][]summaries.SummaryNode),
				}
				calleeToSumm[callee] = emptySumm
			}
		}

		// Iterate callees in a deterministic order: calleeToSumm is keyed by *ssa.Function, so
		// ranging over it directly varies per run, and that order is observable as the order of
		// each callee's candidate summary list in res.
		callees := make([]*ssa.Function, 0, len(calleeToSumm))
		for callee := range calleeToSumm {
			callees = append(callees, callee)
		}
		slices.SortFunc(callees, func(a, b *ssa.Function) int {
			return strings.Compare(a.String(), b.String())
		})
		for _, callee := range callees {
			summ := calleeToSumm[callee]
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

// calledSummaryNode is a summaryNode scoped to a specific calling context.
//
// The call site is part of its identity because a callee's summary graph is shared across every call
// site targeting it: the same ParamNode object represents that parameter at every site. Without the
// call site, nodes for two calls to the same function merge, and a flow can enter at one site and
// leave at another, inventing flows between arguments of unrelated calls.
//
// A nil call means the function being analyzed, whose own nodes have no enclosing call.
type calledSummaryNode struct {
	summaryNode
	call *dataflow.CallNode
}

func (n calledSummaryNode) String() string {
	pathStr := n.path.String()
	if n.call == nil {
		return graphNodeDesc(n.node) + pathStr
	}
	return fmt.Sprintf("%s_%s%s", graphNodeDesc(n.call), graphNodeDesc(n.node), pathStr)
}

// varID returns n's identity for naming maxsat variables. Unlike String it is guaranteed unique per
// distinct (frame, node, path), because it is built from GraphNode.LongID -- "#<summary id>.<node
// id>" -- rather than from rendered source text.
//
// String is not usable for this. It renders a call frame as the call site's SSA text, and two
// distinct call nodes can render identically: `return f() + f()` yields two CallNodes that both print
// as `call:t2()`. graphNodeDesc's fallback for node kinds it does not name explicitly is worse still,
// being just %T plus %v. Colliding names silently merge two variables into one, which conflates the
// facts they stand for -- an edge blocked at one call site would be blocked at the other, and the
// identical-summary equivalences between them would degrade into tautologies.
func (n calledSummaryNode) varID() string {
	callID := "#0"
	if n.call != nil {
		callID = n.call.LongID()
	}
	return callID + ":" + n.node.LongID() + n.path.String()
}

// edge represents a inter or intra-procedural taint flow edge between two nodes.
// It can be hard or soft.
type edge struct {
	from    calledSummaryNode
	to      calledSummaryNode
	isSoft  bool
	isIntra bool
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

// calleeFlowKey identifies a callee summary edge in the callee's own vocabulary, independent of which
// call site observed it.
//
// A callee's summary is one fact per edge, shared by every call site targeting it. Representing it
// per call site and reconciling afterwards is what buildCalleeSummaryConstrs used to do, by matching
// rendered signature strings across sites -- which silently related nothing when two sites named the
// same edge at different access paths. Deriving the maxsat variable from this key instead makes the
// sharing structural: there is no per-site variable left to assign independently.
//
// The endpoints keep their access paths, since two flows between the same positions at different
// paths are different facts. Comparing endpoints by position alone, when needed, is
// WithObjectPath("") on the summary node.
type calleeFlowKey struct {
	callee *ssa.Function
	from   summaries.SummaryNode
	to     summaries.SummaryNode
}

// String returns the key's textual form, used to name its maxsat variable. SummaryNode.String
// renders the access path outside the parenthesized position, so distinct edges get distinct names.
func (k calleeFlowKey) String() string {
	return fmt.Sprintf("%s|%v->%v", k.callee.String(), k.from, k.to)
}

// calleeFlowKeyOf returns the callee summary edge e stands for, if it is one. Only a soft
// intra-procedural edge inside a callee's frame is a summary edge; hard edges are real graph edges and
// keep their per-vertex identity.
func calleeFlowKeyOf(e edge) (calleeFlowKey, bool) {
	if !e.isSoft || e.from.call == nil || e.from.call != e.to.call {
		return calleeFlowKey{}, false
	}
	callee := e.from.call.Callee()
	if callee == nil {
		return calleeFlowKey{}, false
	}
	from, ok := frontendNode(e.from.summaryNode)
	if !ok {
		return calleeFlowKey{}, false
	}
	to, ok := frontendNode(e.to.summaryNode)
	if !ok {
		return calleeFlowKey{}, false
	}
	return calleeFlowKey{callee: callee, from: from, to: to}, true
}

// newMayFlowLit creates a boolean variable representing the dataflow edge from→to.
func newMayFlowLit(e edge) maxsat.Lit {
	if k, ok := calleeFlowKeyOf(e); ok {
		return maxsat.Var(k.String())
	}
	return maxsat.Var(e.from.varID() + "->" + e.to.varID())
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

		// A node with no summary representation (notably a global) cannot appear in a callee summary.
		from, ok := frontendNode(e.from.summaryNode)
		if !ok {
			continue
		}
		to, ok := frontendNode(e.to.summaryNode)
		if !ok {
			continue
		}
		if slices.Contains(flows.Flows[from], to) {
			continue
		}
		flows.Flows[from] = append(flows.Flows[from], to)
		calleeFlows[callee] = flows
	}

	return calleeFlows, nil
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
