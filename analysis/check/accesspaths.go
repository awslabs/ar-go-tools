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

// This file holds the access-path precision decisions made while inferring callee summaries: every
// answer to "how deeply should this node be tracked?".
//
// Field sensitivity here is demand-driven. Tracking a position at depth k means one vertex per access
// path of its type up to k, and each of those becomes its own maxsat variable, so precision nobody asks
// for is paid for in problem size and in spurious co-optimal models.
//
// Precision is decided per position, by a bound (see pathbound.go). A bound is a tree over field names,
// so the descent stops at different depths on different branches, and the access paths it admits form a
// partition of the position's memory: no two of them overlap, and together they cover all of it. That is
// what makes truncation a function into the enumerated set, so each concrete access path has exactly one
// representative and the encoding can never name the same memory twice.
//
// Three sources contribute to a bound, all joined before construction starts:
//
//  1. The summary being checked, and its must-not-flows: the access paths they name.
//
//  2. During construction, per edge: findMatchingPaths in callees.go decides which paths an edge
//     produces from the intra-procedural analysis's own access-path information.
//
//  3. For callee outputs: a callee's body has not been analyzed, so it has no per-field information of
//     its own; its outputs are tracked only as deeply as some caller is observed to read them
//     (calleeOutputDemand).
//
// The callee input side is the one asymmetry, and it is a *naming* decision rather than a precision one.
// A callee's summary graph is shared by all of its call sites -- the same ParamNode object represents
// that parameter at every site -- while the maxsat encoding names a summary edge partly by its access
// path. Two sites disagreeing about how deeply to track a callee input would give the same summary fact
// two unrelated variable names, the solver would assign them independently, and the reported summary
// would be the union of both. So calleeInputNames picks one depth per callee input: the shallowest any
// site enters it at, since an input's path is inherited from the caller rather than derived from a
// signature position, and a path above the bound's frontier would have to be *expanded* into the
// frontier beneath it -- one edge becoming several -- which a per-edge projection cannot do.
//
// Naming coarsely does not coarsen what the callee is checked at. calleeInputBounds computes the join of
// every site's demand and that bound travels with the deduced summary into the callee's own check, so
// the callee still has to account for every distinction any site relied on.
//
// checkCalleeVocabulary in callees.go enforces the result, and fails the run if any callee position ends
// up named at two overlapping access paths on the same side.
package check

import (
	"slices"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

// -----------------------------------------------------------------------------
// Stage 3: callee output vocabulary
// -----------------------------------------------------------------------------

// calleeOutput identifies a position in a callee's signature that can carry data out, in the
// callee's own terms and independently of which call site reaches it: a result index, or a
// parameter index for a pointer-like parameter written through.
type calleeOutput struct {
	callee *ssa.Function
	isRet  bool
	index  int
}

// calleeOutputDemand computes, per callee output, the access path bound that output is represented at
// across the whole of g: the join of the bounds each call site reads it at.
//
// Aggregating per output position rather than per call site is what gives the callee's outputs one
// vocabulary. calleeInputBounds does the same for inputs.
func calleeOutputDemand(g *dataflow.SummaryGraph) map[calleeOutput]lengthBound {
	demand := make(map[calleeOutput]lengthBound)
	record := func(output calleeOutput, callerNode dataflow.GraphNode, tupleIndex int) {
		if callerNode == nil {
			return
		}
		demand[output] = joinLengthBounds(demand[output], boundOfPaths(readPaths(callerNode, tupleIndex)))
	}

	for _, callees := range g.Callees {
		for callee, callNode := range callees {
			if callee == nil || callNode == nil {
				continue
			}
			// Return values. A single-result call has one ReturnValNode whose Index is 0, and
			// expandCalleeOutput's tuple filter treats a negative edge index as "any", so the demand
			// query mirrors that by passing the index through unchanged.
			for i := range callee.Signature.Results().Len() {
				record(calleeOutput{callee: callee, isRet: true, index: i}, callNode, i)
			}
			// Output parameters. Only pointer-like ones can be outputs, which is the same filter
			// allCalleeOutputVertices applies.
			for i, arg := range callNode.Args() {
				if i >= len(callee.Params) || !isPointerLike(callee.Params[i].Type()) {
					continue
				}
				record(calleeOutput{callee: callee, isRet: false, index: i}, arg, -1)
			}
		}
	}

	// No sort is needed: pathsOfTypeUnderBound walks the type's fields in declaration order and looks
	// the bound up per field, so its output order does not depend on the order the read paths were
	// discovered in.
	return demand
}

// calleeOutputOf returns the signature position a callee output node occupies, and whether it has
// one.
func calleeOutputOf(callee *ssa.Function, out dataflow.GraphNode) (calleeOutput, bool) {
	if callee == nil {
		return calleeOutput{}, false
	}
	switch n := out.(type) {
	case *dataflow.ParamNode:
		return calleeOutput{callee: callee, isRet: false, index: n.Index()}, true
	case *dataflow.ReturnValNode:
		return calleeOutput{callee: callee, isRet: true, index: n.Index()}, true
	default:
		// Free variables and globals have no call-site-derived position; they stay field-insensitive.
		return calleeOutput{}, false
	}
}

// calleeOutputPaths returns the access paths at which a callee output node is represented, taken
// solely from that output's aggregated demand.
//
// A callee has no per-field information of its own during construction, since its body has not been
// analyzed, so naming a field on one of its outputs is only worth doing if a caller distinguishes
// that field. The parent's intra-procedural analysis already recorded which ones it does, as the
// source access paths on the edges leaving the call-site value.
//
// Without this, a value returned from a call and then read at two different fields has both reads
// conflated: one soft edge standing for "the whole returned value" cannot tell y.First from y.Second,
// and reports flows the field-sensitive graph does not have. An output with no recorded demand stays
// field-insensitive.
func calleeOutputPaths(
	demand map[calleeOutput]lengthBound, callee *ssa.Function, out dataflow.GraphNode,
) []path {
	output, ok := calleeOutputOf(callee, out)
	if !ok {
		return []path{{}}
	}
	return pathsOfTypeUnderBound(out.Type(), demand[output])
}

// readPaths reports the access paths the caller reads callerNode at: those appearing as a source on its
// outgoing edges. tupleIndex, when non-negative, restricts the query to edges carrying that tuple index,
// mirroring expandCalleeOutput's filter so a multi-value call doesn't demand depth for one return value
// because a different one is read field-sensitively.
func readPaths(callerNode dataflow.GraphNode, tupleIndex int) []path {
	var relevant []path
	callerVal := nodeSsaValue(callerNode)
	for nextNode, edgeInfos := range callerNode.Out() {
		// Skip edges that just pass the same value along, e.g. into another call. The caller is not
		// distinguishing a field of the value there, and the access paths on such an edge are an
		// artifact of the value having been enumerated field-sensitively in the first place (see
		// isRedundantIntraSelfFlow). Counting them as demand would give every value that is merely
		// forwarded a field-sensitive output for fields nobody reads.
		if v := nodeSsaValue(nextNode); v != nil && v == callerVal {
			continue
		}
		for _, ei := range edgeInfos {
			if tupleIndex >= 0 && ei.Index >= 0 && tupleIndex != ei.Index {
				continue
			}
			for inPath := range ei.RelPath {
				p := newPath(inPath, maxPathLen)
				if p.len() == 0 {
					continue
				}
				if !slices.Contains(relevant, p) {
					relevant = append(relevant, p)
				}
			}
		}
	}
	return relevant
}

// -----------------------------------------------------------------------------
// Stage 4a: callee input vocabulary
// -----------------------------------------------------------------------------

// calleeInputNames returns, per callee input node, the access path depth that node is *named* at in the
// encoding: the shallowest depth any call site enters it at.
//
// This is a naming decision, not a precision one. A summary edge's maxsat variable is keyed by its
// endpoints, so a callee input must have exactly one name per side; two sites entering at different
// depths would otherwise produce two overlapping names for the same memory and hence two independent
// variables for one fact, which checkCalleeVocabulary rejects. Truncating to the shallowest depth is the
// only projection available here, because a path above the bound's frontier would have to be *expanded*
// into the frontier beneath it -- one edge becoming several -- which a per-edge projection cannot do.
//
// Naming coarsely does not coarsen what the callee is checked at: calleeInputBounds computes the join of
// every site's demand and that travels with the deduced summary, so the callee's own check still
// distinguishes everything any site relied on.
func calleeInputNames(fg *flowGraph) map[dataflow.GraphNode]int {
	names := make(map[dataflow.GraphNode]int)
	for _, ge := range fg.allEdges() {
		if !isCalleeSummaryEdge(ge) {
			continue
		}
		d := ge.from.path.len()
		if cur, ok := names[ge.from.node]; !ok || d < cur {
			names[ge.from.node] = d
		}
	}
	return names
}

// calleeInputBounds returns, per callee, the access path bound its call sites entered it at: the join
// over every site of the paths that site used.
//
// A callee's summary is one set of facts shared by all of its call sites, so it is checked against a
// single bound. Taking the *shallowest* depth any site entered at would place two access paths under one
// name that a finer site told apart, so a flow between them becomes implicit and no summary at that
// bound can deny it. A caller that discharged a must-not-flow by relying on the callee lacking that flow
// would then be relying on something unprovable. The join is the coarsest bound that keeps every site's
// distinctions.
//
// The result is keyed by signature position rather than by graph node, because it has to survive into
// the callee's own check, where the graph nodes are different objects.
func calleeInputBounds(fg *flowGraph) calleeBounds {
	demands := make(calleeBounds)
	for _, ge := range fg.allEdges() {
		if !isCalleeSummaryEdge(ge) {
			continue
		}
		callee := ge.from.call.Callee()
		if callee == nil {
			continue
		}
		for _, end := range []vertex{ge.from, ge.to} {
			sn, ok := frontendNode(summaryNode{node: end.node})
			if !ok {
				// A position with no exported name -- a global -- cannot carry a bound across the
				// boundary, so it stays field-insensitive.
				continue
			}
			demands.demand(callee, newBoundPosition(sn), end.path)
		}
	}
	return demands
}

// isCalleeSummaryEdge reports whether ge is one of the unknown may-flow edges that make up a callee's
// inferred summary: a soft edge from one node to another within the same callee's frame. This is the
// gedge-level form of the test calleeFlowKeyOf applies to an edge.
func isCalleeSummaryEdge(ge gedge) bool {
	return ge.isSoft && ge.from.call != nil && ge.from.call == ge.to.call
}

// -----------------------------------------------------------------------------
// Stage 4b: canonicalization
// -----------------------------------------------------------------------------

// canonicalize deduplicates each vertex's adjacency list and fixes its order, then rebuilds the
// vertex set from what survives. Without it the maxsat encoding depends on the order construction
// happened to discover edges in, which makes variable numbering and the solver's choice among
// co-optimal models unstable across runs.
//
// Must run only after construction converges, since it rebuilds fg.vertices from fg.out.
func canonicalize(fg *flowGraph) {
	newOut := make(map[vertexKey][]gedge, len(fg.out))
	for k, edges := range fg.out {
		seen := make(map[gedge]struct{}, len(edges))
		kept := make([]gedge, 0, len(edges))
		for _, e := range edges {
			if _, dup := seen[e]; dup {
				continue
			}
			seen[e] = struct{}{}
			kept = append(kept, e)
		}
		newOut[k] = sortGedges(kept)
	}
	fg.out = newOut

	fg.vertices = make(map[vertexKey]struct{}, len(fg.vertices))
	for _, seed := range fg.seeds {
		fg.vertices[seed.key()] = struct{}{}
	}
	for _, edges := range fg.out {
		for _, e := range edges {
			fg.vertices[e.from.key()] = struct{}{}
			fg.vertices[e.to.key()] = struct{}{}
		}
	}
	for k := range fg.expanded {
		if _, ok := fg.vertices[k]; !ok {
			delete(fg.expanded, k)
		}
	}
}
