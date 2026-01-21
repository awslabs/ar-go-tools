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

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// checkSummaryMostGeneral checks the soundness of want by comparing it to the most-general summary
// of g.
// The most-general summary assumes that all function inputs (parameters) flow to all function
// outputs (parameters and all return values).
// It returns the difference of the most-general summary and want: all of the flows in want that are
// not in the most-general summary.
// This difference is the set of must-not-flows: the flows that must not exist (there cannot be a
// possible data flow in the program) for the summary to be sound.
func checkSummaryMostGeneral(g *dataflow.SummaryGraph, wantFlows []flow) ([]flow, error) {
	gotFlows, err := mostGeneralFlows(g, wantFlows)
	if err != nil {
		return nil, fmt.Errorf("failed to compute most-general flows: %v", err)
	}
	if len(gotFlows) < len(wantFlows) {
		return gotFlows, fmt.Errorf("most-general flows is less than summary flows")
	}

	return funcutil.Diff(gotFlows, wantFlows), nil
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
func mostGeneralFlows(g *dataflow.SummaryGraph, wantFlows []flow) ([]flow, error) {
	var flows []flow
	seen := make(map[flow]struct{})
	var inputs []graphNode
	var outputs []graphNode
	for _, param := range g.Params {
		nodes, err := enumeratePaths(param, wantFlows)
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate param paths: %v", err)
		}
		inputs = append(inputs, nodes...)
		outputs = append(outputs, nodes...)
	}
	for _, fv := range g.FreeVars {
		nodes, err := enumeratePaths(fv, wantFlows)
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate free var paths: %v", err)
		}
		inputs = append(inputs, nodes...)
		outputs = append(outputs, nodes...)
	}
	for _, rets := range g.Returns {
		for _, ret := range rets {
			nodes, err := enumeratePaths(ret, wantFlows)
			if err != nil {
				return nil, fmt.Errorf("failed to enumerate return paths: %v", err)
			}
			outputs = append(outputs, nodes...)
		}
	}
	for _, input := range inputs {
		for _, output := range outputs {
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

func enumeratePaths(node dataflow.GraphNode, wantFlows []flow) ([]graphNode, error) {
	if len(wantFlows) == 0 {
		return []graphNode{{node, [maxPathLen]string{}}}, nil
	}

	// Check if this node appears with paths anywhere in the summary
	longestPathLen := 0
	hasMatch := false
	for _, flow := range wantFlows {
		// Check both inputs and outputs to determine if we need field sensitivity
		for _, n := range []graphNode{flow.from, flow.to} {
			if n.node == node {
				hasMatch = true
				if n.path.len() > longestPathLen {
					longestPathLen = n.path.len()
				}
			}
		}
	}

	// Node doesn't appear in summary at all - return base node
	if !hasMatch {
		return []graphNode{{node, [maxPathLen]string{}}}, nil
	}

	// No path sensitivity required: return just the node.
	if longestPathLen == 0 {
		return []graphNode{{node, [maxPathLen]string{}}}, nil
	}

	// Path sensitivity required: return nodes with all paths of the length of the longest path
	// (plus shorter paths).
	var res []graphNode
	allPaths := dataflow.AccessPathsOfType(node.Type())
	for _, path := range allPaths {
		gn := newGraphNode(node, path)
		if gn.path.len() > longestPathLen {
			var truncated [maxPathLen]string
			copy(truncated[:], gn.path[:longestPathLen])
			gn.path = truncated
		}
		res = append(res, gn)
	}

	return res, nil
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

	return flows, nil
}
