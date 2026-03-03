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

	// Target path in gotFlow must start with target path in wantFlow
	wantPath := wantFlow.to.path.String()
	gotPath := gotFlow.to.path.String()

	// Empty path matches everything
	if wantPath == emptyPath {
		return true
	}

	return strings.HasPrefix(gotPath, wantPath)
}

// filterFlowsTypes tries to prove that the flows do not hold by a simple type
// analysis: if the node being flowed to is a pointer-like parameter, then the flow may exist.
// It returns all the flows that have pointer-like parameter outputs, or whose outputs are not
// parameters.
func filterFlowsTypes(flows []flow) []flow {
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
			panic(fmt.Errorf("invalid flow to node type: %v (%T)", to, to))
		}
	}

	return unproven
}

// mostGeneralFlows returns the most-general summary for the function in g.
// Params and free variables are both inputs and outputs.
// Returns are only outputs.
func mostGeneralFlows(g *dataflow.SummaryGraph, prec *precisions) ([]flow, error) {
	var flows []flow
	seen := make(map[flow]struct{})
	var inputs []graphNode
	var outputs []graphNode
	for _, param := range g.Params {
		inputNodes, err := enumeratePaths(param, prec.inputs.nodePathLen[param])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate input param paths: %v", err)
		}
		inputs = append(inputs, inputNodes...)

		outputNodes, err := enumeratePaths(param, prec.outputs.nodePathLen[param])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate output param paths: %v", err)
		}
		outputs = append(outputs, outputNodes...)
	}
	for _, fv := range g.FreeVars {
		inputNodes, err := enumeratePaths(fv, prec.inputs.nodePathLen[fv])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate input free var paths: %v", err)
		}
		inputs = append(inputs, inputNodes...)

		outputNodes, err := enumeratePaths(fv, prec.outputs.nodePathLen[fv])
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate output free var paths: %v", err)
		}
		outputs = append(outputs, outputNodes...)
	}
	for _, rets := range g.Returns {
		for _, ret := range rets {
			nodes, err := enumeratePaths(ret, prec.outputs.nodePathLen[ret])
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

	return flows, nil
}

// TODO remove error
func enumeratePaths(node dataflow.GraphNode, pathLen int) ([]graphNode, error) {
	var res []graphNode
	allPaths := leafPathsUpTo(node.Type(), pathLen)
	for _, path := range allPaths {
		res = append(res, graphNode{node: node, path: path})
	}

	return res, nil
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
		panic(fmt.Errorf("no access paths for type %v", t))
	}

	return res
}

func summaryFlows(g *dataflow.SummaryGraph, summ summaries.DetailedSummary) ([]flow, error) {
	var flows []flow
	for input, outputs := range summ.Flows {
		in := findNode(g, input)
		if in == nil {
			return nil, fmt.Errorf("could not find node for %v", input)
		}
		for _, output := range outputs {
			out := findNode(g, output)
			if out == nil {
				return nil, fmt.Errorf("could not find node for %v", output)
			}
			flows = append(flows, flow{
				from: newGraphNode(in, input.Path()),
				to:   newGraphNode(out, output.Path()),
			})
		}
	}

	// Filter out redundant flows: e.g., a -> b implies a.f -> b.f
	var filtered []flow
	for _, fl1 := range flows {
		skip := false
		if fl1.from.path.len() > 0 && fl1.to.path.len() > 0 {
			for _, fl2 := range flows {
				if fl1 == fl2 {
					continue
				}
				if fl1.from.node == fl2.from.node && fl1.to.node == fl2.to.node {
					if fl1.from.path.isCoveredBy(fl2.from.path) && fl1.to.path.isCoveredBy(fl2.to.path) {
						skip = true
						break
					}
				}
			}
		}
		if skip {
			continue
		}
		filtered = append(filtered, fl1)
	}

	return filtered, nil
}
