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

// ValidateSummary rejects summaries that become empty after redundant-flow normalization.
func ValidateSummary(want summaries.DetailedSummary) error {
	if len(want.Flows) == 0 {
		return nil
	}
	for from, tos := range want.Flows {
		for _, to := range tos {
			if !isSyntacticRedundantContainmentFlow(from, to) {
				return nil
			}
		}
	}
	return fmt.Errorf(
		"summary contains only redundant containment flows (e.g. %s): once redundant flows are filtered out, "+
			"this summary carries no information", firstFlowDesc(want))
}

// isSyntacticRedundantContainmentFlow validates summary syntax without graph resolution.
func isSyntacticRedundantContainmentFlow(from, to summaries.SummaryNode) bool {
	return summaries.IsRedundantContainmentFlow(from, to)
}

// firstFlowDesc returns a deterministic description of one flow in want, for use in an error
// message. want must be non-empty.
func firstFlowDesc(want summaries.DetailedSummary) string {
	var froms []summaries.SummaryNode
	for from := range want.Flows {
		froms = append(froms, from)
	}
	slices.SortFunc(froms, func(a, b summaries.SummaryNode) int {
		return strings.Compare(a.String(), b.String())
	})
	from := froms[0]
	tos := want.Flows[from]
	to := slices.MinFunc(tos, func(a, b summaries.SummaryNode) int {
		return strings.Compare(a.String(), b.String())
	})
	return fmt.Sprintf("%s -> %s", from, to)
}

// checkSummaryMostGeneral checks the soundness of want by comparing it to the most-general summary
// of g.
// The most-general summary assumes that all function inputs (parameters) flow to all function
// outputs (parameters and all return values).
// It returns the difference of the most-general summary and want: all of the flows in want that are
// not in the most-general summary.
// This difference is the set of must-not-flows: the flows that must not exist (there cannot be a
// possible data flow in the program) for the summary to be sound.
func checkSummaryMostGeneral(
	logger *config.LogGroup, g *dataflow.SummaryGraph, bounds nodeBounds, wantFlows []flow,
) ([]flow, error) {
	gotFlows, err := mostGeneralFlows(g, bounds)
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
	return wantFlow.to.path.subsumes(gotFlow.to.path)
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

// mostGeneralFlows returns the most-general summary for the function in g: every flow between access
// paths the bounds admit, from an input position to an output position.
//
// Params and free variables are both inputs and outputs. Returns are only outputs. Inputs and outputs
// are enumerated at the same bound per position, since a pointer parameter that is both is one piece
// of memory.
func mostGeneralFlows(g *dataflow.SummaryGraph, bounds nodeBounds) ([]flow, error) {
	var flows []flow
	var inputs []summaryNode
	var outputs []summaryNode
	for _, param := range g.Params {
		nodes := enumerateBounded(param, bounds)
		inputs = append(inputs, nodes...)
		outputs = append(outputs, nodes...)
	}
	for _, fv := range g.FreeVars {
		nodes := enumerateBounded(fv, bounds)
		inputs = append(inputs, nodes...)
		outputs = append(outputs, nodes...)
	}
	for _, rets := range g.Returns {
		for _, ret := range rets {
			outputs = append(outputs, enumerateBounded(ret, bounds)...)
		}
	}
	for _, input := range inputs {
		for _, output := range outputs {
			flows = append(flows, flow{from: input, to: output})
		}
	}

	var err error
	flows, err = withoutRedundantGraphFlows(flows)
	if err != nil {
		return nil, err
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

// withoutRedundantGraphFlows converts to frontend flows so all summary producers share one
// normalization rule.
func withoutRedundantGraphFlows(flows []flow) ([]flow, error) {
	frontendFlows := make([]summaries.Flow, 0, len(flows))
	for _, graphFlow := range flows {
		from, fromOK := frontendNode(graphFlow.from)
		to, toOK := frontendNode(graphFlow.to)
		if !fromOK || !toOK {
			return nil, fmt.Errorf("cannot normalize non-frontend flow %v", graphFlow)
		}
		frontendFlows = append(frontendFlows, summaries.Flow{From: from, To: to})
	}

	retained := summaries.FilterRedundantFlows(frontendFlows)
	used := make([]bool, len(flows))
	filtered := make([]flow, 0, len(retained))
	for _, retainedFlow := range retained {
		found := false
		for index, frontendFlow := range frontendFlows {
			if used[index] || frontendFlow.From.String() != retainedFlow.From.String() ||
				frontendFlow.To.String() != retainedFlow.To.String() {
				continue
			}
			used[index] = true
			filtered = append(filtered, flows[index])
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("failed to map normalized flow %v back to its graph flow", retainedFlow)
		}
	}
	return filtered, nil
}

// enumerateBounded returns node paired with each access path its bound admits.
func enumerateBounded(node dataflow.GraphNode, bounds nodeBounds) []summaryNode {
	paths := bounds.paths(node)
	res := make([]summaryNode, 0, len(paths))
	for _, p := range paths {
		res = append(res, summaryNode{node: node, path: p})
	}
	return res
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
	// Normalize the frontend representation before resolving it against graph nodes.
	normalized := summ.WithoutRedundantFlows()

	var flows []flow
	for input, outputs := range normalized.Flows {
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
	return flows, nil
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
