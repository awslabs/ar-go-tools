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
)

// checkSummaryMostGeneral checks the soundness of want by comparing it to the most-general summary
// of g.
// The most-general summary assumes that all function inputs (parameters) flow to all function
// outputs (parameters and all return values).
func checkSummaryMostGeneral(g *dataflow.SummaryGraph, want summaries.DetailedSummary) checkResult {
	gotFlows := mostGeneralFlows(g)
	wantFlows := summaryFlows(g, want)
	if len(gotFlows) < len(wantFlows) {
		panic(fmt.Errorf("most-general flows is less than summary flows"))
	}

	unproven := difference(gotFlows, wantFlows)
	return newCheckResult(unproven, General)
}

// checkSummaryTypes tries to prove that the flows in bad do not hold by a simple type analysis:
// if the node being flowed to is a non-pointer-like parameter, then the flow cannot exist.
func checkSummaryTypes(bad []flow) checkResult {
	var unproven []flow
	for _, fl := range bad {
		switch to := fl.to.(type) {
		case *dataflow.ParamNode:
			if isPointerLike(to.Type()) {
				unproven = append(unproven, fl)
			}
		case *dataflow.ReturnValNode:
			unproven = append(unproven, fl)
		default:
			panic(fmt.Errorf("invalid flow to node type: %v (%T)", to, to))
		}
	}

	return newCheckResult(unproven, Types)
}

// mostGeneralFlows returns the most-general summary for the function in g.
// TODO include free variables as inputs and outputs
func mostGeneralFlows(g *dataflow.SummaryGraph) []flow {
	var flows []flow
	seen := make(map[flow]struct{})
	for _, input := range g.Params {
		for _, output := range g.Params {
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

		for _, outputs := range g.Returns {
			for _, output := range outputs {
				fl := flow{from: input, to: output}
				if _, ok := seen[fl]; ok {
					continue
				}
				flows = append(flows, fl)
				seen[fl] = struct{}{}
			}
		}
	}

	return flows
}

func summaryFlows(g *dataflow.SummaryGraph, summ summaries.DetailedSummary) []flow {
	var flows []flow
	for input, outputs := range summ.Flows {
		in := findNode(g, input)
		for _, output := range outputs {
			out := findNode(g, output)
			flows = append(flows, flow{from: in, to: out})
		}
	}

	return flows
}
