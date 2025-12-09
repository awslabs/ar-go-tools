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
	"errors"
	"fmt"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
)

// checkSummaryNaive computes the full inter-procedural data flow summary of f.
// If there are any flows in bad that are not in the summary, then the result is unsound.
func checkSummaryNaive(ctx context.Context, s *dataflow.State, f *ssa.Function, bad []flow) (checkResult, error) {
	gotSummary, err := FullySummarize(ctx, s, f)
	if err != nil {
		return newCheckResult(bad, Naive),
			fmt.Errorf("failed to fully summarize function %s: %w", f.RelString(nil), err)
	}

	var unproven []flow
	for _, flow := range bad {
		for input, outputs := range gotSummary.Flows {
			for _, output := range outputs {
				if input == flow.from && output == flow.to {
					continue
				}
				unproven = append(unproven, flow)
			}
		}
	}

	return newCheckResult(unproven, Naive), nil
}

// FullSummary is the full inter-procedurally-generated data flow summary for a function.
type FullSummary struct {
	Graph *dataflow.SummaryGraph                      // Graph is the summary graph.
	Flows map[dataflow.GraphNode][]dataflow.GraphNode // Flows are from function inputs to outputs.
}

// FullySummarize computes the full data flow summary for function f.
// This uses both the intra- and inter-procedural data flow analyses.
func FullySummarize(ctx context.Context, s *dataflow.State, f *ssa.Function) (FullSummary, error) {
	if len(s.FlowGraph.Summaries) == 0 {
		return FullSummary{}, fmt.Errorf("data flow state is not initialized")
	}

	graph, ok := s.FlowGraph.Summaries[f]
	if !ok {
		return FullSummary{}, fmt.Errorf("failed to find summary for function %s", f)
	}
	if !graph.Constructed || graph.IsInterfaceContract || graph.IsPreSummarized {
		graph = dataflow.NewSummaryGraph(s, f, dataflow.GetUniqueFunctionID(), nil, nil)
		graph.IsInterfaceContract = false
		graph.IsPreSummarized = false
		graph.Constructed = false
		_, err := dataflow.RunIntraProcedural(ctx, s, graph)
		if err != nil {
			return FullSummary{},
				fmt.Errorf("failed to run intra-procedural data flow analysis: %v", err)
		}
	}

	flows := make(map[dataflow.GraphNode][]dataflow.GraphNode)
	for _, param := range graph.Params {
		v := dataflow.NewFuncInputVisitor()
		v.Visit(ctx, s, dataflow.NodeWithTrace{Node: param})
		// if there are no flows, don't add them
		if len(v.Flows()) == 0 {
			continue
		}
		flows[param] = v.Flows()
	}
	if s.Report.HasErrors() {
		errs := s.Report.CheckError()
		return FullSummary{}, fmt.Errorf(
			"failed to run the inter-procedural data flow analysis: %w",
			errors.Join(errs...))
	}
	s.FlowGraph.Sync()

	for fn, completeSummary := range s.FlowGraph.Summaries {
		if fn == f {
			res := FullSummary{Graph: completeSummary, Flows: flows}
			// Even if a global node isn't explicitly visited, it may still be in the summary
			if len(completeSummary.AccessGlobalNodes) > 0 {
				return res, fmt.Errorf("invalid summary: %w", dataflow.ErrGlobal)
			}
			return res, nil
		}
	}

	panic("failed to find computed summary in graph")
}
