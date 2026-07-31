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
	"fmt"
	"go/types"
	"slices"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

// checkSummaryMostGeneral checks the soundness of want by comparing it to the most-general summary
// of g.
// The most-general summary assumes that all function inputs (parameters) flow to all function
// outputs (parameters and all return values).
// It returns the difference of the most-general summary and want: all of the flows in want that are
// not in the most-general summary.
// This difference is the set of must-not-flows: the flows that must not exist (there cannot be a
// possible data flow in the program) for the summary to be sound.
func checkSummaryMostGeneral(
	logger *config.LogGroup, g *dataflow.SummaryGraph, prec *precisions, wantFlows []flow,
) ([]flow, error) {
	gotFlows, err := mostGeneralFlows(g, prec)
	if err != nil {
		return nil, fmt.Errorf("failed to compute most-general flows: %v", err)
	}
	if len(gotFlows) < len(wantFlows) {
		return gotFlows, fmt.Errorf("most-general flows is less than summary flows")
	}

	if logger.LogsDebug() {
		logger.Debugf("want flows:\n")
		for _, fl := range wantFlows {
			logger.Debugf("\t%v\n", fl)
		}
		logger.Debugf("most-general summary for %s:\n", g.Parent)
		for _, fl := range gotFlows {
			logger.Debugf("\t%v\n", fl)
		}
	}

	return diffFlowsWithPaths(gotFlows, wantFlows), nil
}

// diffFlowsWithPaths returns flows in gotFlows that are not covered by wantFlows.
// A flow in gotFlows is covered by a flow in wantFlows if:
// - The source nodes match and source paths match exactly
// - The target nodes match and the target path in gotFlows starts with the target path in wantFlows
func diffFlowsWithPaths(gotFlows, wantFlows []flow) []flow {
	var mustNotFlows []flow
	for _, got := range gotFlows {
		covered := false
		for _, want := range wantFlows {
			if flowCovers(want, got) {
				covered = true
				break
			}
		}
		if !covered {
			mustNotFlows = append(mustNotFlows, got)
		}
	}
	return mustNotFlows
}

// flowCovers returns true if wantFlow covers gotFlow.
// A flow covers another if the source matches exactly and the target path is a prefix.
func flowCovers(wantFlow, gotFlow flow) bool {
	// Source must match exactly (both node and path)
	if wantFlow.from.node != gotFlow.from.node {
		return false
	}
	if wantFlow.from.path != gotFlow.from.path {
		return false
	}

	// Target node must match
	if wantFlow.to.node != gotFlow.to.node {
		return false
	}

	// Target path in gotFlow must have the target path in wantFlow as a (segment-wise) prefix.
	// Empty path matches everything.
	return wantFlow.to.path.isCoveredBy(gotFlow.to.path)
}

// filterFlowsTypes tries to prove that the flows do not hold by a simple type
// analysis: if the node being flowed to is a pointer-like parameter, then the flow may exist.
// It returns all the flows that have pointer-like parameter outputs, or whose outputs are not
// parameters.
func filterFlowsTypes(flows []flow) ([]flow, error) {
	var unproven []flow
	for _, fl := range flows {
		switch to := fl.to.node.(type) {
		case *dataflow.ParamNode:
			if isPointerLike(to.Type()) {
				unproven = append(unproven, fl)
			}
		case *dataflow.FreeVarNode:
			// Free variables are always pointer-like.
			unproven = append(unproven, fl)
		case *dataflow.ReturnValNode:
			// Returns can always be outputs.
			unproven = append(unproven, fl)
		default:
			return nil, fmt.Errorf("invalid flow to node type: %v (%T)", to, to)
		}
	}

	return unproven, nil
}

// mostGeneralFlows returns the most-general summary for the function in g.
// Params and free variables are both inputs and outputs.
// Returns are only outputs.
func mostGeneralFlows(g *dataflow.SummaryGraph, prec *precisions) ([]flow, error) {
	var flows []flow
	seen := make(map[flow]struct{})
	var inputs []summaryNode
	var outputs []summaryNode
	for _, param := range g.Params {
		inputNodes, err := enumeratePaths(param, prec.inputs.nodePathLen[param], prec.inputs.nodePaths[param])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate input param paths: %v", err)
		}
		inputs = append(inputs, inputNodes...)

		outputNodes, err := enumeratePaths(param, prec.outputs.nodePathLen[param], prec.outputs.nodePaths[param])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate output param paths: %v", err)
		}
		outputs = append(outputs, outputNodes...)
	}
	for _, fv := range g.FreeVars {
		inputNodes, err := enumeratePaths(fv, prec.inputs.nodePathLen[fv], prec.inputs.nodePaths[fv])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate input free var paths: %v", err)
		}
		inputs = append(inputs, inputNodes...)

		outputNodes, err := enumeratePaths(fv, prec.outputs.nodePathLen[fv], prec.outputs.nodePaths[fv])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate output free var paths: %v", err)
		}
		outputs = append(outputs, outputNodes...)
	}
	for _, rets := range g.Returns {
		for _, ret := range rets {
			nodes, err := enumeratePaths(ret, prec.outputs.nodePathLen[ret], prec.outputs.nodePaths[ret])
			if err != nil {
				return nil, fmt.Errorf("failed to enumerate output return paths: %v", err)
			}
			outputs = append(outputs, nodes...)
		}
	}
	for _, input := range inputs {
		for _, output := range outputs {
			// If the input is not field-sensitive (path len of 0) and the output node is an input
			// node, then do not enumerate the paths of its outputs, even if the outputs are
			// supposed to be field-sensitive. This is because a flow from x -> x.f is implicit and
			// doesn't make sense to include in a summary.
			if input.node == output.node && input.path.isCoveredBy(output.path) {
				continue
			}

			// We don't count self-flows (input flows to same input as an output) because the data
			// flows to and from the parameter when used as an argument at a callsite are part of
			// the data flow of the caller's summary, not the callee's.
			if input == output {
				continue
			}

			fl := flow{from: input, to: output}
			if _, ok := seen[fl]; ok {
				continue
			}
			flows = append(flows, fl)
			seen[fl] = struct{}{}
		}
	}

	// g.Params, g.FreeVars and g.Returns are maps, so inputs and outputs are enumerated in random
	// order. The resulting flow order is not cosmetic: these flows become the must-not-flows, whose
	// order decides the order of the clauses handed to maxsat, and the solver breaks ties between
	// equally-optimal models in the order it sees them.
	slices.SortFunc(flows, func(a, b flow) int {
		return strings.Compare(a.String(), b.String())
	})

	return flows, nil
}

// TODO remove error
//
// relevantPaths, if non-empty, restricts the enumeration to relevantPathsOfType's collapsed
// enumeration instead of every leaf path up to pathLen (see relevantPathsOfType for why this is
// sound and does not lose precision for the paths that matter).
func enumeratePaths(node dataflow.GraphNode, pathLen int, relevantPaths []path) ([]summaryNode, error) {
	var res []summaryNode
	allPaths := relevantPathsOfType(node.Type(), pathLen, relevantPaths)
	for _, path := range allPaths {
		res = append(res, summaryNode{node: node, path: path})
	}

	return res, nil
}

// relevantPathsOfType returns the access paths of t needed to represent every path that is either:
//   - a path in relevantPaths, enumerated in full (i.e. exactly as leafPathsUpTo would, down to
//     depth k along that path), or
//   - part of the "uncovered" remainder of t's access-path tree: a path outside every relevantPaths
//     entry, represented by exactly one path per branch point where the relevant paths and the
//     uncovered remainder diverge, rather than one path per leaf beneath that branch point.
//
// This is used in place of leafPathsUpTo when enumerating a node's access paths for the purpose of
// building candidate flows (see mostGeneralFlows): since the resulting flows are only interesting
// insofar as they are covered by (relevant to), or represent the absence of a flow not covered by,
// some entry in relevantPaths, there is no need to separately enumerate every leaf beneath a branch
// that contains no relevant path at all -- a single path standing for that whole subtree suffices,
// and (unlike a sentinel value) remains a real, meaningful access path that downstream
// path-sensitive analyses (e.g. checkWritesPtr, checkReads) can match against normally.
//
// If relevantPaths is empty, nothing in t is relevant, so the whole tree collapses to a single
// path (t's root, i.e. path{}) rather than falling back to full leaf enumeration: a node with no
// relevant paths at all still needs exactly one entry to represent "any access path into this
// node," not zero and not every leaf. Callers that want every leaf enumerated regardless of
// relevance should call leafPathsUpTo directly instead of passing an empty relevantPaths here.
func relevantPathsOfType(t types.Type, k int, relevantPaths []path) []path {
	if k == 0 || len(relevantPaths) == 0 {
		return []path{{}}
	}

	var res []path

	type el struct {
		t types.Type
		p path
		d int // d is the current depth (number of field accesses)
		// onRelevantPath is true if p is a (possibly empty) prefix of some entry in relevantPaths,
		// i.e. this branch must still be recursed into to expose the relevant leaf(s) beneath it.
		// A branch with onRelevantPath == false has already diverged from every relevant path, and
		// is emitted as a single leaf without further recursion.
		onRelevantPath bool
	}
	stack := []el{{t: t, p: path{}, d: 0, onRelevantPath: true}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// A branch that has diverged from every relevant path represents the whole subtree beneath
		// it: emit its own path as a single leaf, regardless of depth or further structure.
		if !cur.onRelevantPath {
			res = append(res, cur.p)
			continue
		}

		// If we've reached the max depth, add the current path if non-empty
		if cur.d == k {
			if cur.d > 0 {
				res = append(res, cur.p)
			}
			continue
		}

		switch t := cur.t.(type) {
		case *types.Pointer:
			// Pointers don't add to path depth
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d, onRelevantPath: cur.onRelevantPath})
		case *types.Named:
			// Named types don't add to path depth
			stack = append(stack, el{t: t.Underlying(), p: cur.p, d: cur.d, onRelevantPath: cur.onRelevantPath})
		case *types.Array:
			// Arrays don't add to path depth (we don't track indices)
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d, onRelevantPath: cur.onRelevantPath})
		case *types.Slice:
			// Slices don't add to path depth
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d, onRelevantPath: cur.onRelevantPath})
		case *types.Map:
			// Maps don't add to path depth (we don't track keys)
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d, onRelevantPath: cur.onRelevantPath})
		case *types.Struct:
			if t.NumFields() == 0 {
				// A struct with no fields (e.g. the common `_ struct{}` marker idiom) has
				// nowhere left to descend into, so it is itself a leaf.
				res = append(res, cur.p)
				continue
			}
			// Each struct field adds to the path. A field continues on a relevant path only if
			// extending cur.p with that field name is still a prefix of (or equal to) some entry
			// in relevantPaths.
			for i := range t.NumFields() {
				fld := t.Field(i)
				newP := cur.p
				newP[cur.d] = fld.Name()
				stack = append(stack, el{
					t: fld.Type(), p: newP, d: cur.d + 1,
					onRelevantPath: pathIsPrefixOfAny(newP, cur.d+1, relevantPaths),
				})
			}
		default:
			res = append(res, cur.p)
		}
	}

	if len(res) == 0 {
		// NOTE Should be unreachable.
		panic(fmt.Errorf("no access paths for type %v", t))
	}

	return res
}

// pathIsPrefixOfAny returns true if p (whose first n segments are populated) is a segment-wise
// prefix of, or equal to, some entry in paths -- i.e. whether continuing to recurse along p could
// still reach one of paths' entries (or, once n reaches that entry's own length, has reached it
// exactly).
func pathIsPrefixOfAny(p path, n int, paths []path) bool {
	for _, rp := range paths {
		rpLen := rp.len()
		if n > rpLen {
			continue
		}
		matches := true
		for i := range n {
			if p[i] != rp[i] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

// leafPathsUpTo returns all access paths from type t to its leaf (scalar) types, up to a maximum
// depth of k.
//
// It traverses through pointers, named types, arrays, slices, maps, and struct fields to find all
// reachable scalar values.
func leafPathsUpTo(t types.Type, k int) []path {
	if k == 0 {
		return []path{[maxPathLen]string{}}
	}

	var res []path

	type el struct {
		t types.Type
		p path
		d int // d is the current depth (number of field accesses)
	}
	stack := []el{{t: t, p: path{}, d: 0}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// If we've reached the max depth, add the current path if non-empty
		if cur.d == k {
			if cur.d > 0 {
				res = append(res, cur.p)
			}
			continue
		}

		switch t := cur.t.(type) {
		case *types.Pointer:
			// Pointers don't add to path depth
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d})
		case *types.Named:
			// Named types don't add to path depth
			stack = append(stack, el{t: t.Underlying(), p: cur.p, d: cur.d})
		case *types.Array:
			// Arrays don't add to path depth (we don't track indices)
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d})
		case *types.Slice:
			// Slices don't add to path depth
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d})
		case *types.Map:
			// Maps don't add to path depth (we don't track keys)
			stack = append(stack, el{t: t.Elem(), p: cur.p, d: cur.d})
		case *types.Struct:
			if t.NumFields() == 0 {
				// A struct with no fields (e.g. the common `_ struct{}` marker idiom) has
				// nowhere left to descend into, so it is itself a leaf.
				res = append(res, cur.p)
				continue
			}
			// Each struct field adds to the path
			for i := range t.NumFields() {
				fld := t.Field(i)
				newPath := cur.p
				newPath[cur.d] = fld.Name()
				stack = append(stack, el{t: fld.Type(), p: newPath, d: cur.d + 1})
			}
		default:
			res = append(res, cur.p)
		}
	}

	if len(res) == 0 {
		// NOTE Should be unreachable.
		panic(fmt.Errorf("no access paths for type %v", t))
	}

	return res
}

func summaryFlows(s *State, g *dataflow.SummaryGraph, summ summaries.DetailedSummary) ([]flow, error) {
	var flows []flow
	for input, outputs := range summ.Flows {
		in, err := findNode(g, input)
		if in == nil || err != nil {
			return nil, fmt.Errorf("could not find node for %v: %v", input, err)
		}
		for _, output := range outputs {
			out, err := findNode(g, output)
			if out == nil || err != nil {
				return nil, fmt.Errorf("could not find node for %v: %v", output, err)
			}
			flows = append(flows, flow{
				from: newSummaryNode(in, input.Path()),
				to:   newSummaryNode(out, output.Path()),
			})
		}
	}

	// Filter out redundant flows: e.g., a -> b implies a.f -> b.f.
	// Also return an error for self flows.
	var filtered []flow
	for i, fl1 := range flows {
		skip := false
		if fl1.from.node == fl1.to.node &&
			fl1.from.path.isCoveredBy(fl1.to.path) && fl1.to.path.isCoveredBy(fl1.from.path) {
			// Same node AND same (or overlapping) access path: this is a true self-flow (e.g.
			// r.Params -> r.Params), not merely a flow between two different fields of the same
			// node (e.g. r.Params -> r.Body, which has from.node == to.node but distinct paths
			// and must not be dropped).
			s.Logger.Warnf("flow %v is a redundant self-flow\n", fl1)
			skip = true
		} else {
			for j, fl2 := range flows {
				if i == j {
					continue
				}
				if fl1.from.node == fl2.from.node && fl1.to.node == fl2.to.node {
					if fl2.from.path.isCoveredBy(fl1.from.path) && fl2.to.path.isCoveredBy(fl1.to.path) {
						// fl2 covers fl1: skip fl1 unless fl1 also covers fl2 (equal), in which
						// case use the index to break the tie.
						if !(fl1.from.path.isCoveredBy(fl2.from.path) && fl1.to.path.isCoveredBy(fl2.to.path)) ||
							j < i {

							s.Logger.Warnf("flow %v is redundant with %v\n", fl1, fl2)
							skip = true
							break
						}
					}
				}
			}
		}
		if skip {
			continue
		}
		filtered = append(filtered, fl1)
	}

	if !slices.Equal(flows, filtered) {
		s.Logger.Warnf(
			"removed redundant flows from summary:\n\toriginal: %v\n\tfiltered: %v\n",
			flows, filtered)
	}

	return filtered, nil
}

func findNode(g *dataflow.SummaryGraph, sn summaries.SummaryNode) (dataflow.GraphNode, error) {
	var res dataflow.GraphNode
	var reserr error
	g.ForAllNodes(func(n dataflow.GraphNode) {
		// TODO use new iteration protocol to implement ForAllNodes to break when found
		ok, err := matchesNode(sn, n)
		if err != nil {
			reserr = err
			return
		}
		if ok {
			res = n
		}
	})
	return res, reserr
}

func matchesNode(snode summaries.SummaryNode, gnode dataflow.GraphNode) (bool, error) {
	switch s := snode.(type) {
	case summaries.ReceiverSNode:
		if param, ok := gnode.(*dataflow.ParamNode); ok {
			if param.Graph().Parent.Signature.Recv() == nil {
				return false, fmt.Errorf("expected function for recv summary node to have a receiver")
			}
			return param.Index() == 0, nil
		}
	case summaries.ArgumentSNode:
		if param, ok := gnode.(*dataflow.ParamNode); ok {
			if param.Graph().Parent.Signature.Recv() != nil {
				return (s.Name != "" && param.SsaNode().Name() == s.Name) ||
					param.Index() == s.Index+1, nil
			}
			return (s.Name != "" && param.SsaNode().Name() == s.Name) ||
				param.Index() == s.Index, nil
		}
	case summaries.ReturnSNode:
		if ret, ok := gnode.(*dataflow.ReturnValNode); ok {
			return ret.Index() == s.Index, nil
		}
	case summaries.FreeVarSNode:
		if fv, ok := gnode.(*dataflow.FreeVarNode); ok {
			return fv.SsaNode().Name() == s.Name, nil
		}
	default:
		return false, fmt.Errorf("unhandled summary node type: %T", snode)
	}

	return false, nil
}
