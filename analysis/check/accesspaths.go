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
// Field sensitivity here is demand-driven. Tracking a node at depth k means one vertex per access path
// of its type up to k, and each of those becomes its own maxsat variable, so precision nobody asks for
// is paid for in problem size and in spurious co-optimal models. The decisions therefore happen in
// four stages, in this order:
//
//  1. From the summary being checked, before construction. The summary's own flows say which nodes
//     need which paths.
//
//  2. During construction, per edge. findMatchingPaths in callees.go decides which paths an edge
//     produces from the intra-procedural analysis's own access-path information.
//
//  3. During construction, for callee outputs. A callee's body has not been analyzed, so it has no
//     per-field information of its own; its outputs are tracked only as deeply as some caller is
//     observed to read them.
//
//  4. After construction has converged. Two passes narrow what the graph ended up with:
//     calleeInputDemand fixes one vocabulary per callee input, and coarsen drops precision on
//     dead-end vertices that nothing can distinguish.
//
// Stages 3 and 4 exist for the same underlying reason and are easy to confuse. A callee's summary
// graph is shared by all of its call sites -- the same ParamNode object represents that parameter
// at every site -- while the maxsat encoding names a summary edge partly by its access path. So if
// two call sites disagree about how deeply to track a callee node, the same summary fact acquires
// two unrelated variable names, the solver assigns them independently, and the reported summary is
// the union of both: more general than any single site's model justified. Both stages force one
// vocabulary per callee node, differing only in which direction they can move:
//
//   - Outputs (stage 3) take the *deepest* depth any site reads, aggregated per callee output before
//     the vertices exist, so construction can materialize them at that depth.
//   - Inputs (stage 4) take the *shallowest*, because an input's path is inherited from the caller
//     rather than derived from a signature position, and by the time that divergence is visible the
//     vertices already exist. A vertex at the empty path stands for every path under it and cannot be
//     split per field without re-running construction.
//
// checkCalleeVocabulary in callees.go enforces the result of both, and fails the run if any callee
// position ends up named at two overlapping granularities.
package check

import (
	"fmt"
	"slices"
	"strings"

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

// pathDemand is the access-path precision one callee output needs: the deepest path any call site
// reads it at, and the union of the specific paths they read.
type pathDemand struct {
	longest  int
	relevant []path
}

// calleeOutputDemand computes, per callee output, the precision that output is represented at across
// the whole of g -- the max depth and the union of relevant paths over every call site of that
// callee.
//
// Aggregating per output position rather than per call site is what gives the callee's outputs one
// vocabulary. calleeInputDemand does the same for inputs.
func calleeOutputDemand(g *dataflow.SummaryGraph) map[calleeOutput]pathDemand {
	demand := make(map[calleeOutput]pathDemand)
	record := func(output calleeOutput, callerNode dataflow.GraphNode, tupleIndex int) {
		if callerNode == nil {
			return
		}
		longest, relevant := readDepth(callerNode, tupleIndex)
		cur := demand[output]
		cur.longest = max(cur.longest, longest)
		for _, p := range relevant {
			if !slices.Contains(cur.relevant, p) {
				cur.relevant = append(cur.relevant, p)
			}
		}
		demand[output] = cur
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

	for output, d := range demand {
		// RelPath is a map, so relevant paths arrive in random order, and relevantPathsOfType's
		// output order follows theirs -- which reaches the maxsat variable order via the soft edges.
		slices.SortFunc(d.relevant, func(a, b path) int {
			return strings.Compare(a.String(), b.String())
		})
		demand[output] = d
	}
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
func calleeOutputPaths(demand map[calleeOutput]pathDemand, callee *ssa.Function, out dataflow.GraphNode) []path {
	output, ok := calleeOutputOf(callee, out)
	if !ok {
		return []path{{}}
	}
	d, ok := demand[output]
	if !ok || d.longest == 0 {
		return []path{{}}
	}
	return relevantPathsOfType(out.Type(), d.longest, d.relevant)
}

// readDepth reports how deeply the caller reads callerNode: the deepest access path appearing as a
// source on its outgoing edges, and the specific paths seen. tupleIndex, when non-negative,
// restricts the query to edges carrying that tuple index, mirroring expandCalleeOutput's filter so
// a multi-value call doesn't demand depth for one return value because a different one is read
// field-sensitively.
func readDepth(callerNode dataflow.GraphNode, tupleIndex int) (int, []path) {
	var relevant []path
	longest := 0
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
				longest = max(longest, p.len())
				if !slices.Contains(relevant, p) {
					relevant = append(relevant, p)
				}
			}
		}
	}
	return longest, relevant
}

// -----------------------------------------------------------------------------
// Stage 4a: callee input vocabulary
// -----------------------------------------------------------------------------

// calleeInputDemand returns, per callee input node, the shallowest access path depth any call site
// enters that node at.
//
// This is the input-side counterpart of calleeOutputDemand; see the file comment for why one
// vocabulary per callee is required and why this side can only move shallower.
//
// Collapsing is the safe direction: it only makes the inferred summary coarser. If it blocks a flow the
// callee really has, the callee check fails to prove it and unprovenFlowsAfterCalleeCheck re-opens the
// edges, and matchesReportedFlow uses pathsOverlap so a coarsened edge still matches the callee's finer
// reported flow.
//
// fg.toEdge applies the result, which is what keeps it out of reach of the encoding: every route from
// the graph to a maxsat variable name or a reported summary node goes through that projection.
func calleeInputDemand(fg *flowGraph) map[dataflow.GraphNode]int {
	demand := make(map[dataflow.GraphNode]int)
	for _, ge := range fg.allEdges() {
		if !isCalleeSummaryEdge(ge) {
			continue
		}
		d := ge.from.path.len()
		if cur, ok := demand[ge.from.node]; !ok || d < cur {
			demand[ge.from.node] = d
		}
	}
	return demand
}

// isCalleeSummaryEdge reports whether ge is one of the unknown may-flow edges that make up a callee's
// inferred summary: a soft edge from one node to another within the same callee's frame. This is the
// gedge-level form of the test calleeFlowKeyOf applies to an edge.
func isCalleeSummaryEdge(ge gedge) bool {
	return ge.isSoft && ge.from.call != nil && ge.from.call == ge.to.call
}

// -----------------------------------------------------------------------------
// Stage 4b: coarsening
// -----------------------------------------------------------------------------

// coarsen collapses each dead-end vertex to the shallowest access path the maxsat encoding can
// still tell apart, returning how many were coarsened. It also canonicalizes adjacency order so the
// encoding does not depend on the order construction discovered edges in.
//
// Only vertices with no outgoing edges are eligible, since their path cannot affect a downstream
// edge that does not exist. What can still tell them apart is the depth each node is named at by
// the summary under check and its must-not-flows, which is what distinguished records. Keeping
// deeper siblings apart only multiplies soft edges: a callee output the caller never looks at
// becomes one free variable per field, making every subset of them an equally optimal model.
//
// Must run only after construction converges. Coarsening removes distinctions, the opposite of
// construction's add-only invariant, so merging early can merge two vertices that only look
// indistinguishable because the edge separating them has not been discovered yet.
//
// Named vertices and seeds keep their paths; see the postconditions below for why.
func coarsen(fg *flowGraph, distinguished map[dataflow.GraphNode]int) (int, error) {
	isSeed := make(map[vertexKey]bool, len(fg.seeds))
	for _, seed := range fg.seeds {
		isSeed[seed.key()] = true
	}

	// floor is the depth a node's vertices may not be collapsed below. It combines the depth the
	// encoding names the node at with the deepest path any *live* vertex of that node uses, so that
	// collapsing stays uniform across call sites: coarsening one call site's copy of an output but not
	// another's would produce two granularities for the same summary edge, and the solver could then
	// satisfy a must-not-flow clause through the coarse copy while the fine copies stay true.
	floor := make(map[dataflow.GraphNode]int, len(distinguished))
	for n, k := range distinguished {
		floor[n] = k
	}
	for _, seed := range fg.seeds {
		floor[seed.node] = max(floor[seed.node], seed.path.len())
	}
	for _, edges := range fg.out {
		for _, e := range edges {
			floor[e.from.node] = max(floor[e.from.node], e.from.path.len())
		}
	}

	coarsened := 0
	newOut := make(map[vertexKey][]gedge, len(fg.out))
	for k, edges := range fg.out {
		seen := make(map[gedge]struct{}, len(edges))
		kept := make([]gedge, 0, len(edges))
		for _, e := range edges {
			// Only the destination can be a dead end: a source has this very edge leaving it.
			if to, ok := coarserVertex(fg, isSeed, floor, e.to); ok {
				if to.path.len() < floor[to.node] {
					// A path shortened below the node's floor stops the must-not-flow that
					// names it from matching, turning an unproven flow into a proven one
					return 0, fmt.Errorf(
						"coarsening %v to %v dropped below its floor of %d", e.to, to, floor[to.node])
				}
				if len(fg.out[to.key()]) > 0 {
					// Merging onto a vertex that has outgoing edges splices this dead end onto
					// unrelated successors, letting the solver satisfy a must-not-flow clause
					// without asserting the edge the flow needs.
					return 0, fmt.Errorf(
						"coarsening %v merged it onto %v, which has outgoing edges", e.to, to)
				}
				coarsened++
				e.to = to
			}
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
	return coarsened, nil
}

// coarserVertex returns v at the shallowest path coarsen may collapse it to, and whether that is
// actually shallower than v's own path.
//
// Collapsing stops short of a path already occupied by a vertex with outgoing edges. Merging into
// one would splice this dead end onto that vertex's successors, chaining soft edges that represent
// unrelated hypotheses: a callee's output parameter collapsed onto the same parameter in its role
// as an *input* would let the solver route a flow in through the parameter and back out through the
// callee's other outputs, satisfying a must-not-flow clause without asserting the edge the flow
// needs.
func coarserVertex(
	fg *flowGraph, isSeed map[vertexKey]bool, floor map[dataflow.GraphNode]int, v vertex,
) (vertex, bool) {
	if isSeed[v.key()] || len(fg.out[v.key()]) > 0 {
		return v, false
	}
	for k := floor[v.node]; k < v.path.len(); k++ {
		c := v
		c.path = v.path.truncate(k)
		if len(fg.out[c.key()]) > 0 {
			continue
		}
		return c, true
	}
	return v, false
}
