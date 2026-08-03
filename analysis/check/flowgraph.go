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
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
)

// vertex is a state in the flow graph: a calledSummaryNode plus the traversal state the construction
// fixpoint needs.
//
// The call stack is deliberately not part of a vertex. Only the innermost frame (the embedded call) is
// kept, which is what lets a node reached from many different call sites be expanded once rather than
// once per route -- the property that makes construction scale (e.g. aws-sdk-go's
// Request.Handlers.*.Run(r), where one parameter is reached from dozens of call sites).
type vertex struct {
	calledSummaryNode
	status dataflow.VisitorNodeStatus
	// closureTrace names the MakeClosure site whose bound variables this vertex's free variables
	// correspond to. It is the closure analogue of call: a closure's creation site and its
	// invocation site differ, and an output reaching a free variable must route back to the bound
	// variables of the site that created the closure, not of the site that invoked it.
	//
	// It is a stack because closures nest (expandBoundVar pushes, the output paths pop). Only the
	// innermost frame is ever read for routing (.Label, or .Parent() to pop one level); the deeper
	// ancestors are read only by vertexID, i.e. they only affect identity. That is a cost, not a
	// benefit: it prevents vertices differing solely in closure history from merging, and it is why
	// expandBoundVar needs a lasso guard to converge. Recording the closure frame on the edge, as
	// gedge.call already does for ordinary calls, would remove both.
	closureTrace *dataflow.NodeTree[*dataflow.ClosureNode]
}

func (v vertex) String() string {
	return graphNodeDesc(v.node) + v.path.String()
}

// vertexKey is a vertex's identity for deduplication, with pointer-only fields projected to their
// semantic content.
//
// vertex must not be used as a map key directly: status.TracingInfo is allocated fresh by every
// closureTracingInfo.Next call (unlike NodeTree.Add, which interns), so two semantically identical
// closure-tracing states compare unequal. Keying on that pointer defeats memoization entirely and
// the graph grows without bound. What actually determines expansion is the free-variable index and
// the closure, so that is what the key carries; the full status stays on the vertex because
// PopClosure needs the prev chain.
type vertexKey struct {
	node           dataflow.GraphNode
	path           path
	statusKind     dataflow.VisitorKind
	tracingIndex   int
	tracingClosure *dataflow.SummaryGraph
	closureTrace   *dataflow.NodeTree[*dataflow.ClosureNode]
	call           *dataflow.CallNode
}

// key returns v's deduplication identity. See vertexKey for why this projection is needed.
func (v vertex) key() vertexKey {
	k := vertexKey{
		node:         v.node,
		path:         v.path,
		statusKind:   v.status.Kind,
		tracingIndex: -1,
		closureTrace: v.closureTrace,
		call:         v.call,
	}
	if v.status.TracingInfo != nil {
		k.tracingIndex = v.status.TracingInfo.Index
		k.tracingClosure = v.status.CurrentClosure()
	}
	return k
}

// withNode returns a copy of v at a different dataflow node, keeping the access path, traversal
// status and frame.
func (v vertex) withNode(n dataflow.GraphNode) vertex {
	v.node = n
	return v
}

// at returns a copy of v relocated to node n at access path p in call's frame, keeping the traversal
// state (status and closure trace).
func (v vertex) at(n dataflow.GraphNode, p path, call *dataflow.CallNode) vertex {
	v.node = n
	v.path = p
	v.call = call
	return v
}

// newVertex builds a vertex for n at access path p in call's frame, with the given traversal state.
func newVertex(
	n dataflow.GraphNode, p path, call *dataflow.CallNode,
	status dataflow.VisitorNodeStatus, closureTrace *dataflow.NodeTree[*dataflow.ClosureNode],
) vertex {
	return vertex{
		calledSummaryNode: calledSummaryNode{
			summaryNode: summaryNode{node: n, path: p},
			call:        call,
		},
		status:       status,
		closureTrace: closureTrace,
	}
}

// gedge is a flow graph edge. It carries the same information as the edge type the maxsat encoding
// consumes: hard/soft (known vs. unknown may-flow), intra/inter-procedural, and the call site it
// crosses.
type gedge struct {
	from, to vertex
	call     *dataflow.CallNode // nil for an edge that doesn't cross a call
	isSoft   bool
	isIntra  bool
}

func (e gedge) String() string {
	var hardness string
	if e.isSoft {
		hardness = "soft"
	} else {
		hardness = "hard"
	}
	var kind string
	if e.isIntra {
		kind = "intra"
	} else {
		kind = "inter"
	}
	return fmt.Sprintf("[%s][%s] %v->%v", kind, hardness, e.from, e.to)
}

// flowGraph is the taint flow graph: a deduplicated set of vertices, each expanded at most once,
// with the outgoing edges discovered for each.
type flowGraph struct {
	// seeds are the input vertices construction started from, one per input node.
	seeds []vertex
	// vertices is every vertex discovered, expanded or not.
	vertices map[vertexKey]struct{}
	// expanded is the vertices whose outgoing edges have been computed; the rest are on the
	// worklist.
	expanded map[vertexKey]struct{}
	// out is the adjacency list.
	out map[vertexKey][]gedge
	// outputPaths gives, per callee output, the access paths that output is represented at. It is
	// computed once for the whole analyzed function so that every call site of a callee shares one
	// summary vocabulary; see calleeOutputDemand in accesspaths.go.
	outputPaths map[calleeOutput]pathDemand
	// inputPaths gives, per callee input node, the access path depth that node is named at in the
	// callee's summary vocabulary. It is the counterpart of outputPaths for the input side, where the
	// path cannot be derived from a signature position because it is inherited from the caller; see
	// calleeInputDemand in accesspaths.go.
	inputPaths map[dataflow.GraphNode]int
}

// newFlowGraph returns an empty flowGraph.
func newFlowGraph() *flowGraph {
	return &flowGraph{
		vertices: make(map[vertexKey]struct{}),
		expanded: make(map[vertexKey]struct{}),
		out:      make(map[vertexKey][]gedge),
	}
}

// addVertex registers v, returning true if it is newly discovered (so the caller pushes it onto the
// worklist).
func (fg *flowGraph) addVertex(v vertex) bool {
	k := v.key()
	if _, ok := fg.vertices[k]; ok {
		return false
	}
	fg.vertices[k] = struct{}{}
	return true
}

// isExpanded reports whether v's outgoing edges have been computed.
func (fg *flowGraph) isExpanded(v vertex) bool {
	_, ok := fg.expanded[v.key()]
	return ok
}

// markExpanded records that v's outgoing edges have been computed, so later arrivals at v do not
// re-expand it.
func (fg *flowGraph) markExpanded(v vertex) {
	fg.expanded[v.key()] = struct{}{}
}

// allEdges returns every edge, deduplicated and in a deterministic order.
//
// The edge-set consumers (buildHardConstraints, unknownMayFlowEdges) read this rather than scraping
// Order matters as much as contents: these edges become maxsat variables, and maxsat breaks ties
// between equally-optimal models in the order it sees them, so an unordered list makes the choice
// among co-optimal callee summaries vary between runs.
func (fg *flowGraph) allEdges() []gedge {
	var edges []gedge
	seen := make(map[gedge]struct{})
	for _, es := range fg.out {
		for _, e := range es {
			if _, ok := seen[e]; ok {
				continue
			}
			seen[e] = struct{}{}
			edges = append(edges, e)
		}
	}
	slices.SortFunc(edges, func(a, b gedge) int {
		if c := strings.Compare(a.String(), b.String()); c != 0 {
			return c
		}
		// String() omits the call site, so edges differing only by which call they cross would
		// otherwise keep their random relative order.
		return strings.Compare(callDesc(a.call), callDesc(b.call))
	})
	return edges
}

// callDesc returns a stable description of a call site, for ordering.
func callDesc(c *dataflow.CallNode) string {
	if c == nil {
		return ""
	}
	return c.LongID()
}

// addEdge records e and registers both endpoints, reporting which of them were newly discovered.
func (fg *flowGraph) addEdge(e gedge) (fromIsNew, toIsNew bool) {
	fromIsNew = fg.addVertex(e.from)
	toIsNew = fg.addVertex(e.to)
	fg.out[e.from.key()] = append(fg.out[e.from.key()], e)
	return fromIsNew, toIsNew
}

// buildFlowGraph runs the worklist fixpoint starting from src, adding every discovered vertex and
// edge to fg. It is the entry point; everything below it is the per-node successor logic it drives.
func buildFlowGraph(ctx context.Context, s *State, fg *flowGraph, src vertex) error {
	// The seed is never treated as a sink even if isOutputNode(src.node) holds (it always does for
	// a ParamNode, regardless of whether that parameter is an output of the check being
	// performed), so its edges come from expandFrom -- the same successor logic as expandVertex,
	// minus the output-sink guard. Vertices discovered from there on go through expandVertex.
	fg.addVertex(src)
	fg.markExpanded(src)
	edges, err := expandFrom(s, fg, src)
	if err != nil {
		return err
	}

	var worklist []vertex
	// push adds an edge to fg and queues either endpoint that is newly discovered.
	push := func(e gedge) {
		fromIsNew, toIsNew := fg.addEdge(e)
		if fromIsNew {
			worklist = append(worklist, e.from)
		}
		if toIsNew {
			worklist = append(worklist, e.to)
		}
	}

	// Batches are sorted so that discovery order -- and hence which route becomes a vertex's
	// adjacency order, and hence the clause order the maxsat encoding derives from it -- does not
	// depend on Go map iteration order, since expansion walks Out() maps.
	for _, e := range sortGedges(edges) {
		push(e)
	}

	for len(worklist) > 0 {
		if err := checkCancelled(ctx, "flow graph construction"); err != nil {
			return err
		}
		v := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		if fg.isExpanded(v) {
			continue
		}
		fg.markExpanded(v)

		edges, err := expandVertex(s, fg, v)
		if err != nil {
			return err
		}
		for _, e := range sortGedges(edges) {
			push(e)
		}
	}
	return nil
}

// expandFrom computes the seed vertex's outgoing edges. Unlike expandVertex it has no output-sink
// guard: the seed is an input node, which is output-typed (isOutputNode matches any ParamNode) but
// must still be expanded.
func expandFrom(s *State, fg *flowGraph, v vertex) ([]gedge, error) {
	if !v.node.Graph().Constructed {
		return nil, fmt.Errorf("unconstructed summary for function input: %v", v.node)
	}
	return forwardOutEdges(v, v.node.Out())
}

// expandVertex computes v's outgoing edges. buildFlowGraph is responsible for calling it at most
// once per vertex.
//
//gocyclo:ignore
func expandVertex(s *State, fg *flowGraph, v vertex) ([]gedge, error) {
	// Output-typed vertices are sinks, in any frame. For the analyzed function's own outputs this
	// ends the flow. For a callee's outputs and parameters (also output-typed) the continuation
	// back into the caller is computed inline by expandCallNodeArg/expandCalleeOutput.
	if isOutputNode(v.node) {
		return nil, nil
	}

	switch n := v.node.(type) {
	case *dataflow.BoundVarNode:
		return expandBoundVar(s, v, n)

	case *dataflow.FreeVarNode:
		// Never reached directly: taint into a closure's free variable is handled by
		// expandClosureCall, and taint out of one by expandCalleeOutput.
		return nil, fmt.Errorf("node should not be visited: %v", n)

	case *dataflow.ClosureNode:
		return forwardOutEdges(v, n.Out())

	case *dataflow.ParamNode:
		// A non-output ParamNode is only reached via a CallNodeArg crossing into the callee, or via
		// a callee output routed back to the caller -- both of which compute their continuations
		// inline. Reaching here means the caller pushed something it shouldn't have.
		return nil, fmt.Errorf("expandVertex should not be reached with a non-output ParamNode: %v", v)

	case *dataflow.ReturnValNode:
		return nil, fmt.Errorf("expandVertex should not be reached with a ReturnValNode: %v", v)

	case *dataflow.CallNodeArg:
		return expandCallNodeArg(s, fg, v, n)

	case *dataflow.CallNode:
		// Only reached while tracing a closure: this is where the closure is called, so taint flows
		// into its free variables.
		if v.status.Kind == dataflow.ClosureTracing {
			return expandClosureCall(s, fg, v, n)
		}
		return nil, fmt.Errorf("call node %v should not be visited outside closure tracing", n)

	case *dataflow.SyntheticNode, *dataflow.BuiltinCallNode:
		return forwardOutEdges(v, v.node.Out())

	case *dataflow.AccessGlobalNode:
		if n.IsWrite {
			s.Logger.Warnf("unanalyzed write to global node: %v\n", n)
			return nil, nil
		}
		// From a read location taint follows the out edges, but only into reachable functions.
		var edges []gedge
		for nextNode, edgeInfos := range n.Out() {
			if !s.IsReachableFunction(nextNode.Graph().Parent) {
				continue
			}
			for _, edgeInfo := range edgeInfos {
				edges = append(edges, matchingEdgesFrom(v, nextNode, edgeInfo)...)
			}
		}
		return edges, nil

	case *dataflow.BoundLabelNode:
		// TODO Handle bound labels. Returning no edges here is unsound, not merely imprecise: a
		// bound label is a location captured by a closure, so dropping it makes flows through that
		// capture invisible to the graph, and a must-not-flow is proven by the *absence* of a path.
		// Every must-not-flow routed through a bound label therefore comes back proven, silently.
		//
		// transitive_closure.go's BoundLabelNode case is the reference: a bound label flows to the
		// body of the closure that captures it, via DestClosure/DestInfo().MakeClosure, guarding on
		// whether the creating function is reachable.
		//
		// Until then this should at least be *visible*. UnsoundCheckFeatures.NonLocalBoundLabelUsages
		// exists for exactly that, and is already reported and compared by tests -- but nothing ever
		// populates it, so a function using a bound label can currently come back Sound with no
		// indication anywhere. Populating it is the smaller first step and does not require deciding
		// the dataflow question.
		return nil, nil

	case *dataflow.IfNode:
		// Sound to drop: an IfNode is a control-flow condition, not a data flow. Taint reaching a
		// branch condition does not reach the values the branch computes.
		return nil, nil

	default:
		return nil, fmt.Errorf("unhandled graph node type: %T", n)
	}
}

// forwardOutEdges forwards v's taint along every one of node's Out() edges, for node kinds that are
// pure pass-throughs.
func forwardOutEdges(v vertex, outEdges map[dataflow.GraphNode][]dataflow.EdgeInfo) ([]gedge, error) {
	var edges []gedge
	for nextNode, edgeInfos := range outEdges {
		for _, edgeInfo := range edgeInfos {
			edges = append(edges, matchingEdgesFrom(v, nextNode, edgeInfo)...)
		}
	}
	return edges, nil
}

// matchingEdgesFrom returns one edge per access path reachable from v via the real graph edge
// (v.node, nextNode, edgeInfo).
//
// findMatchingPaths is called directly rather than reimplemented; the VisitorNode/NodeWithTrace
// wrappers exist only to satisfy its signature, since it reads nothing but cur.Node,
// cur.AccessPaths[0] and next.Node.
func matchingEdgesFrom(v vertex, nextNode dataflow.GraphNode, edgeInfo dataflow.EdgeInfo) []gedge {
	cur := &dataflow.VisitorNode{
		NodeWithTrace: dataflow.NodeWithTrace{Node: v.node},
		AccessPaths:   []string{v.path.String()},
	}
	next := dataflow.NodeWithTrace{Node: nextNode}
	nextPaths := findMatchingPaths(cur, next, edgeInfo)
	edges := make([]gedge, 0, len(nextPaths))
	for _, np := range nextPaths {
		to := v.at(nextNode, newPath(np, maxPathLen), frameFor(v, nextNode))
		edges = append(edges, gedge{from: v, to: to, isIntra: true})
	}
	return edges
}

// frameFor returns the call frame a step from v to nextNode lands in: v's own frame if nextNode is
// in the same summary graph, otherwise nil (we are back in the analyzed function). Inheriting
// v.call unconditionally would leave the analyzed function's own return/param vertices tagged with
// a callee frame, so they would stop being recognized as its outputs.
func frameFor(v vertex, nextNode dataflow.GraphNode) *dataflow.CallNode {
	if v.node.Graph() == nextNode.Graph() {
		return v.call
	}
	return nil
}

// calleeIsAssumedMostGeneral reports whether a callee with no predefined summary should still have
// its internal edges treated as hard (known) rather than soft (unknown). Standard library functions
// are assumed to have the most general summary -- anything may flow to anything -- so there is
// nothing left to infer.
func calleeIsAssumedMostGeneral(s *State, callee *ssa.Function) bool {
	pos := s.State.Program.Fset.Position(callee.Pos())
	return analysisutil.IsStandardLibFilename(pos.Filename)
}

// expandCallNodeArg crosses from a call-site argument into the callee: it establishes the callee's
// summary graph, then either follows a predefined summary's declared flows or, absent one, assumes
// the argument may reach any of the callee's outputs and routes each back to the caller.
func expandCallNodeArg(s *State, fg *flowGraph, v vertex, argNode *dataflow.CallNodeArg) ([]gedge, error) {
	callSite := argNode.ParentNode()
	callee := callSite.Callee()
	if callee == nil {
		return nil, fmt.Errorf("callsite has no callee")
	}
	callSite.CalleeSummary = dataflow.NewSummaryGraph(
		s.State, callee, dataflow.GetUniqueFunctionID(), nil, nil)
	s.FlowGraph.Summaries[callee] = callSite.CalleeSummary

	param := callSite.CalleeSummary.Parent.Params[argNode.Index()]
	if param == nil {
		return nil, fmt.Errorf("no parameter matching argument in %s", callSite.CalleeSummary.Parent)
	}
	calleeParam := callSite.CalleeSummary.Params[param]
	calleeParamIn := v.at(calleeParam, v.path, callSite)

	// The crossing-in edge, needed by both the predefined and inferred cases.
	edges := []gedge{{from: v, to: calleeParamIn, call: callSite}}

	if summaries.FnHasSummaries(callee) {
		predefEdges, err := expandPredefinedCallee(s, calleeParamIn, callSite)
		if err != nil {
			return nil, err
		}
		return append(edges, predefEdges...), nil
	}

	for _, out := range allCalleeOutputVertices(fg, callee, calleeParamIn) {
		// The callee's own input-to-output edge: unknown (soft) unless the callee is assumed most
		// general. These are the edges whose truth assignment the maxsat encoding infers.
		edges = append(edges, gedge{
			from: calleeParamIn, to: out, call: callSite, isIntra: true,
			isSoft: !calleeIsAssumedMostGeneral(s, callee),
		})
		outEdges, err := expandCalleeOutput(s, callSite, out)
		if err != nil {
			return nil, err
		}
		edges = append(edges, outEdges...)
	}
	return edges, nil
}

// allCalleeOutputVertices enumerates a callee's output nodes (pointer-like parameters and return
// values), each at the access paths calleeOutputPaths determines are needed.
func allCalleeOutputVertices(fg *flowGraph, callee *ssa.Function, calleeIn vertex) []vertex {
	var outputs []vertex
	g := calleeIn.node.Graph()
	g.ForAllNodes(func(n dataflow.GraphNode) {
		if !isOutputNode(n) {
			return
		}
		if param, ok := n.(*dataflow.ParamNode); ok && !isPointerLike(param.Type()) {
			return
		}
		for _, p := range calleeOutputPaths(fg.outputPaths, callee, n) {
			out := calleeIn.at(n, p, calleeIn.call)
			// An input "flowing" to itself carries no information.
			if out.node == calleeIn.node && out.path == calleeIn.path {
				continue
			}
			outputs = append(outputs, out)
		}
	})
	return outputs
}

// expandBoundVar handles taint reaching a variable captured by a closure literal: the closure's
// corresponding free variable becomes tainted, but only once the closure is called. So this moves to
// the ClosureNode in ClosureTracing mode, recording which free variable to follow; the flow into the
// free variable itself happens later, at the call site (expandClosureCall).
func expandBoundVar(s *State, v vertex, bv *dataflow.BoundVarNode) ([]gedge, error) {
	closureNode := bv.ParentNode()
	if !closureNode.IsReachable(s.State) {
		return nil, nil
	}
	closureFn, _ := closureNode.Instr().Fn.(*ssa.Function)
	if closureFn == nil {
		return nil, fmt.Errorf("no function for closure %v of bound var %v", closureNode, bv)
	}
	// NOTE deliberately ignores any pre-constructed summary for the closure.
	closureNode.ClosureSummary = dataflow.NewSummaryGraph(
		s.State, closureFn, dataflow.GetUniqueFunctionID(), nil, nil)
	s.FlowGraph.Summaries[closureFn] = closureNode.ClosureSummary

	to := newVertex(closureNode, v.path, nil,
		dataflow.VisitorNodeStatus{
			Kind:        dataflow.ClosureTracing,
			TracingInfo: v.status.TracingInfo.Next(closureNode.ClosureSummary, bv.Index()),
		},
		v.closureTrace.Add(closureNode))
	// Recursion guard. A closure reached from its own body keeps extending the closure trace, and
	// since NodeTree.Add only interns among an existing node's children, each level is a new node
	// and so a distinct vertex -- the worklist would never converge.
	if to.closureTrace != nil && to.closureTrace.GetLassoHandle() != nil {
		return nil, nil
	}
	// Empty EdgeInfo: findMatchingPaths' fallback decides the outgoing access paths.
	return matchingEdgesTo(v, to, dataflow.EdgeInfo{}), nil
}

// expandClosureCall handles the point where a traced closure is called: taint flows from the
// captured variable into the closure's free variable, and from there to the closure's outputs.
func expandClosureCall(s *State, fg *flowGraph, v vertex, call *dataflow.CallNode) ([]gedge, error) {
	currentClosure := v.status.CurrentClosure()
	if currentClosure == nil {
		return nil, fmt.Errorf("nil closure from call node %v in closure tracing mode", call)
	}
	// NOTE deliberately ignores any pre-constructed summary; there should be none for a closure.
	call.CalleeSummary = dataflow.NewSummaryGraph(
		s.State, currentClosure.Parent, dataflow.GetUniqueFunctionID(), nil, nil)
	s.FlowGraph.Summaries[currentClosure.Parent] = call.CalleeSummary

	if call.CalleeSummary != currentClosure {
		return nil, fmt.Errorf("call node %v callee %v is not the current closure %v",
			call, call.Callee(), currentClosure.Parent)
	}
	fv := currentClosure.Parent.FreeVars[v.status.TracingInfo.Index]
	if fv == nil {
		return nil, fmt.Errorf("no free variable matching bound variable in %s",
			call.CalleeSummary.Parent.String())
	}
	fvNode := call.CalleeSummary.FreeVars[fv]
	fvNode.Graph().Callsites[call.CallSite()] = call

	// Closure tracing ends here: the closure body's free variable has been reached, so the status
	// pops back out of tracing.
	calleeInput := newVertex(fvNode, v.path, call, v.status.PopClosure(), v.closureTrace)
	edges := []gedge{{from: v, to: calleeInput, call: call}}
	// Assume taint flows from the free variable to all the closure's outputs.
	for _, out := range allCalleeOutputVertices(fg, currentClosure.Parent, calleeInput) {
		edges = append(edges, gedge{
			from: calleeInput, to: out, call: call, isIntra: true,
			isSoft: !calleeIsAssumedMostGeneral(s, currentClosure.Parent),
		})
		outEdges, err := expandCalleeOutput(s, call, out)
		if err != nil {
			return nil, err
		}
		edges = append(edges, outEdges...)
	}
	return edges, nil
}

// matchingEdgesTo is matchingEdgesFrom for the closure cases, where the destination's status and
// closure trace differ from the source's: it computes access paths the same way but keeps to's own
// status/closureTrace instead of copying v's.
func matchingEdgesTo(v vertex, to vertex, edgeInfo dataflow.EdgeInfo) []gedge {
	cur := &dataflow.VisitorNode{
		NodeWithTrace: dataflow.NodeWithTrace{Node: v.node},
		AccessPaths:   []string{v.path.String()},
	}
	next := dataflow.NodeWithTrace{Node: to.node}
	nextPaths := findMatchingPaths(cur, next, edgeInfo)
	edges := make([]gedge, 0, len(nextPaths))
	for _, np := range nextPaths {
		dst := to
		dst.path = newPath(np, maxPathLen)
		edges = append(edges, gedge{from: v, to: dst, isIntra: true})
	}
	return edges
}

// expandCalleeOutput routes one of a callee's outputs back into the caller. callSite is the call at
// which out was reached, or nil for a closure body reached via the closure trace.
//
// The caller-side node (the call-site argument, or the call node itself) is deliberately not made a
// vertex of its own. If it were, the worklist would dispatch it through expandVertex and treat this
// output hypothesis as a fresh argument flowing into another call -- which is how an unrelated
// argument at the same call site (e.g. add1's unused "no", reached only as an output hypothesis of
// "b") would get its own callee expansion, chaining unrelated inputs and outputs together. Instead a
// throwaway vertex is used to reuse matchingEdgesFrom's path computation, and the resulting edges
// are rewritten to start at out, skipping it.
func expandCalleeOutput(s *State, callSite *dataflow.CallNode, out vertex) ([]gedge, error) {
	switch n := out.node.(type) {
	case *dataflow.ParamNode:
		// Flows to the call-site argument, then on to that argument's outgoing nodes.
		if !callSite.Graph().Constructed {
			return nil, fmt.Errorf("call site %v of param node %v graph is not constructed", callSite, n)
		}
		arg := callSite.Args()[n.Index()]
		if arg == nil {
			return nil, fmt.Errorf("no matching arg from param %v in call site %v", n, callSite)
		}
		callerOutput := out.at(arg, out.path, nil)
		var edges []gedge
		for nextNode, edgeInfos := range arg.Out() {
			for _, edgeInfo := range edgeInfos {
				for _, e := range matchingEdgesFrom(callerOutput, nextNode, edgeInfo) {
					edges = append(edges, gedge{from: out, to: e.to, call: callSite})
				}
			}
		}
		return edges, nil

	case *dataflow.ReturnValNode:
		// Flows to the call node (the returned value), then on to its outgoing nodes with a
		// matching tuple index. A nil callSite means a closure body reached via the closure trace,
		// where the value flows back to the ClosureNode instead.
		if callSite == nil {
			return expandClosureReturn(s, out, n)
		}
		if !callSite.Graph().Constructed {
			return nil, fmt.Errorf("call site %v of return node %v graph is not constructed", callSite, n)
		}
		callerOutput := out.at(callSite, out.path, nil)
		var edges []gedge
		for nextNode, edgeInfos := range callSite.Out() {
			for _, edgeInfo := range edgeInfos {
				if n.Index() >= 0 && edgeInfo.Index >= 0 && n.Index() != edgeInfo.Index {
					continue
				}
				for _, e := range matchingEdgesFrom(callerOutput, nextNode, edgeInfo) {
					edges = append(edges, gedge{from: out, to: e.to, call: callSite})
				}
			}
		}
		return edges, nil

	case *dataflow.FreeVarNode:
		return expandFreeVarOutput(s, out, n)

	case *dataflow.AccessGlobalNode:
		return nil, nil

	default:
		return nil, fmt.Errorf("invalid output node type: %T", n)
	}
}

// expandClosureReturn routes a value returned from a closure body back to the ClosureNode that
// created it (named by the closure trace), then along that node's outgoing edges.
func expandClosureReturn(s *State, out vertex, ret *dataflow.ReturnValNode) ([]gedge, error) {
	if out.closureTrace == nil || out.closureTrace.Label == nil {
		return nil, fmt.Errorf("no calling context for callee output: %v", out)
	}
	closure := out.closureTrace.Label
	if closure.ClosureSummary == nil {
		return nil, fmt.Errorf(
			"closure summary from %v via trace %v is nil", ret, out.closureTrace)
	}
	if !dataflow.CheckClosureReturns(ret, closure) {
		return nil, fmt.Errorf("return node %v is not from the closure %v in the trace", ret, closure)
	}
	if !closure.Graph().Constructed {
		return nil, fmt.Errorf(
			"closure node %v of return node %v graph is not constructed", closure, ret)
	}
	// As elsewhere, the ClosureNode is not made a vertex of its own: its outgoing edges are computed
	// inline and rewritten to start at out.
	callerOutput := newVertex(closure, out.path, nil, out.status, out.closureTrace.Parent())
	var edges []gedge
	for nextNode, edgeInfos := range closure.Out() {
		for _, edgeInfo := range edgeInfos {
			for _, e := range matchingEdgesFrom(callerOutput, nextNode, edgeInfo) {
				edges = append(edges, gedge{from: out, to: e.to})
			}
		}
	}
	return edges, nil
}

// expandFreeVarOutput handles taint reaching a closure's free variable as an output: the
// corresponding bound variable in the enclosing function is tainted after the closure runs, so the
// flow continues from there.
//
// With a closure trace, the MakeClosure site it names is used; otherwise every site that may refer
// to this free variable is considered, which requires building the inter-procedural graph first
// since ReferringMakeClosures is only populated then.
func expandFreeVarOutput(s *State, out vertex, fv *dataflow.FreeVarNode) ([]gedge, error) {
	if out.closureTrace != nil && out.closureTrace.Label != nil {
		return freeVarEdgesViaClosure(s, out, fv, out.closureTrace.Label)
	}

	s.Logger.Warnf("no closure trace for node %v\n", out)
	s.FlowGraph.BuildGraph(true)
	s.FlowGraph.Sync()
	if len(fv.Graph().ReferringMakeClosures) == 0 {
		// If the enclosing function isn't reachable, the data cannot be flowing here at all; we may
		// have arrived via bound or global variables.
		if !s.IsReachableFunction(fv.Graph().Parent.Parent()) {
			return nil, nil
		}
		return nil, fmt.Errorf("no closure context: no referring make closure nodes from %v", fv)
	}

	var edges []gedge
	for _, makeClosureSite := range fv.Graph().ReferringMakeClosures {
		siteEdges, err := freeVarEdgesViaClosure(s, out, fv, makeClosureSite)
		if err != nil {
			return nil, err
		}
		edges = append(edges, siteEdges...)
	}
	return edges, nil
}

// freeVarEdgesViaClosure routes fv back to the bound variable it corresponds to at closureSite, then
// along that variable's outgoing edges. The bound variable is not made a vertex of its own, which
// would re-enter expandBoundVar and restart closure tracing.
func freeVarEdgesViaClosure(
	s *State, out vertex, fv *dataflow.FreeVarNode, closureSite *dataflow.ClosureNode,
) ([]gedge, error) {
	bvs := closureSite.BoundVars()
	if len(bvs) == 0 {
		return nil, fmt.Errorf("no bound vars for node %v", fv)
	}
	if fv.Index() >= len(bvs) {
		return nil, fmt.Errorf(
			"no bound variable matching free variable in %s", closureSite.ClosureSummary.Parent.String())
	}
	bv := bvs[fv.Index()]
	callerOutput := newVertex(bv, out.path, nil, out.status.PopClosure(), out.closureTrace.Parent())
	var edges []gedge
	for nextNode, edgeInfos := range bv.Out() {
		for _, edgeInfo := range edgeInfos {
			for _, e := range matchingEdgesFrom(callerOutput, nextNode, edgeInfo) {
				edges = append(edges, gedge{from: out, to: e.to})
			}
		}
	}
	return edges, nil
}

// expandPredefinedCallee follows a pre-defined summary's declared arg- and return-flows for
// calleeParamIn's parameter, instead of analyzing the callee's body.
func expandPredefinedCallee(s *State, calleeParamIn vertex, callSite *dataflow.CallNode) ([]gedge, error) {
	calleeParamNode, ok := calleeParamIn.node.(*dataflow.ParamNode)
	if !ok {
		return nil, fmt.Errorf(
			"can only add predefined summary input flows from a callee param, got: %v", calleeParamIn.node)
	}
	callee := callSite.Callee()
	summ, ok := summaries.SummaryOfFunc(callee)
	if !ok {
		return nil, fmt.Errorf("expected pre-defined function %s to have a summary", callee)
	}

	var edges []gedge

	argFlows, err := summ.GetArgFlows(callee)
	if err != nil {
		return nil, fmt.Errorf("failed to get arg flows for pre-defined summary %v: %w", summ, err)
	}
	if len(argFlows) > calleeParamNode.Index() {
		for _, nextArgIdx := range argFlows[calleeParamNode.Index()] {
			nextArg := callSite.Args()[nextArgIdx]
			var calleeOutParam *dataflow.ParamNode
			for _, param := range callSite.CalleeSummary.Params {
				if param.Index() == nextArgIdx {
					calleeOutParam = param
					break
				}
			}
			if calleeOutParam == nil {
				return nil, fmt.Errorf(
					"no corresponding param for arg %v in pre-defined callee summary %v",
					nextArg, callSite.CalleeSummary)
			}
			calleeOut := calleeParamIn.withNode(calleeOutParam)
			callerOutput := calleeParamIn.withNode(nextArg)
			callerOutput.call = nil
			edges = append(edges,
				gedge{from: calleeParamIn, to: calleeOut, call: callSite, isSoft: false, isIntra: true},
				gedge{from: calleeOut, to: callerOutput, call: callSite, isSoft: false, isIntra: false})
			for nextNode, edgeInfos := range callerOutput.node.Out() {
				for _, edgeInfo := range edgeInfos {
					edges = append(edges, matchingEdgesFrom(callerOutput, nextNode, edgeInfo)...)
				}
			}
		}
	}

	retFlows, err := summ.GetReturnFlows(callee)
	if err != nil {
		return nil, fmt.Errorf("failed to get return flows for pre-defined summary %v: %w", summ, err)
	}
	if len(retFlows) > calleeParamNode.Index() {
		for _, retIdx := range retFlows[calleeParamNode.Index()] {
			var callerRets []dataflow.GraphNode
			for nextNode, edgeInfos := range callSite.Out() {
				for _, ei := range edgeInfos {
					if !(retIdx >= 0 && ei.Index >= 0 && retIdx != ei.Index) {
						callerRets = append(callerRets, nextNode)
					}
				}
			}
			// A callee summary records flows to *a* return node with a matching index, so any
			// matching callee return node represents the crossing equally well.
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
				return nil, fmt.Errorf(
					"no corresponding ret for caller rets %v in pre-defined callee summary %v",
					callerRets, callSite.CalleeSummary)
			}
			calleeOut := calleeParamIn.withNode(nextCalleeRet)
			edges = append(edges,
				gedge{from: calleeParamIn, to: calleeOut, call: callSite, isSoft: false, isIntra: true})
			for _, retNode := range callerRets {
				callerOutput := calleeParamIn.withNode(retNode)
				callerOutput.call = nil
				edges = append(edges,
					gedge{from: calleeOut, to: callerOutput, call: callSite, isSoft: false, isIntra: false})
			}
		}
	}

	return edges, nil
}

// sortGedges orders a batch of newly discovered edges deterministically. It sorts in place and
// returns the same slice.
func sortGedges(edges []gedge) []gedge {
	slices.SortFunc(edges, func(a, b gedge) int {
		if c := strings.Compare(a.String(), b.String()); c != 0 {
			return c
		}
		return strings.Compare(callDesc(a.call), callDesc(b.call))
	})
	return edges
}

// toEdge projects a flow graph edge onto the plain edge the maxsat encoding and the summary
// conversion consume. Each endpoint's frame comes from that vertex's own call field, which is part of
// vertex identity precisely so that two calls to the same callee stay separate.
//
// It also canonicalizes the callee-input side to the callee's single vocabulary. Canonicalizing here rather than at each use is what makes the input-side vocabulary consistent by
// construction: every path from the graph to a maxsat variable name (newMayFlowLit) and to a reported
// summary node (mayFlowEdgesToSummaries) goes through this projection, so neither can see a
// per-call-site path. The graph itself keeps its full precision, since vertex-level reachability is
// answered over fg.out, not over these edges.
func (fg *flowGraph) toEdge(e gedge) edge {
	from := summaryNode{node: e.from.node, path: e.from.path}
	if isCalleeSummaryEdge(e) {
		if d, ok := fg.inputPaths[e.from.node]; ok {
			from.path = from.path.truncate(d)
		}
	}
	return edge{
		from: calledSummaryNode{summaryNode: from, call: e.from.call},
		to: calledSummaryNode{
			summaryNode: summaryNode{node: e.to.node, path: e.to.path},
			call:        e.to.call,
		},
		isSoft:  e.isSoft,
		isIntra: e.isIntra,
	}
}

// vertexID returns a stable, unique textual identity for v, used to name the reachability variables
// of the maxsat encoding.
//
// It is derived from v.key() so that there is exactly one definition of vertex identity. The key
// decides when two vertices are the same vertex and the name decides when they are the same maxsat
// fact; if the two drift apart the failure is silent in both directions -- too coarse a key merges
// distinct vertices, and a name omitting a field the key distinguishes conflates two facts.
//
// The rendering is built from GraphNode.LongID rather than source text, since two distinct nodes can
// render identically, and it must not derive from any pointer, because variable names feed the clause
// ordering that decides which of several co-optimal models the solver reports.
func vertexID(v vertex) string {
	k := v.key()
	closure := ""
	if k.tracingClosure != nil {
		closure = strconv.Itoa(int(k.tracingClosure.ID))
	}
	return fmt.Sprintf("%s%s@%s#%d.%d.%s|%s",
		k.node.LongID(), k.path.String(), callDesc(k.call),
		k.statusKind, k.tracingIndex, closure, k.closureTrace.Key())
}

// reachableFrom returns every vertex reachable from src in fg, src included, in a deterministic
// order (breadth-first over the canonicalized adjacency lists coarsen leaves behind).
func reachableFrom(fg *flowGraph, src vertex) []vertex {
	return reachableFromVia(fg, src, nil)
}

// reachableFromVia is reachableFrom restricted to the edges admit accepts. A nil admit accepts all
// of them.
func reachableFromVia(fg *flowGraph, src vertex, admit func(gedge) bool) []vertex {
	seen := map[vertexKey]bool{src.key(): true}
	order := []vertex{src}
	for i := 0; i < len(order); i++ {
		for _, e := range fg.out[order[i].key()] {
			if admit != nil && !admit(e) {
				continue
			}
			if seen[e.to.key()] {
				continue
			}
			seen[e.to.key()] = true
			order = append(order, e.to)
		}
	}
	return order
}
