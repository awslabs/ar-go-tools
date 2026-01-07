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

	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
)

// ClosedInterproceduralSummary is the full inter-procedurally-generated data flow summary for a function.
type ClosedInterproceduralSummary struct {
	Graph *dataflow.SummaryGraph                      // Graph is the summary graph.
	Flows map[dataflow.GraphNode][]dataflow.GraphNode // Flows are from function inputs to outputs.
}

func summaryNodeOfGraphNode(node dataflow.GraphNode) summaries.SummaryNode {
	isMethod := node.Graph().Parent.Signature.Recv() != nil
	switch gnode := node.(type) {
	case *dataflow.ParamNode:
		index := gnode.Index()
		if isMethod && index == 0 {
			return summaries.ReceiverSNode{ObjectPath: ""}
		} else if isMethod {
			index -= 1
		}
		return summaries.ArgumentSNode{
			Name:  gnode.SsaNode().Name(),
			Index: index,
			// TODO: support object access paths
			ObjectPath: "",
		}
	case *dataflow.ReturnValNode:
		return summaries.ReturnSNode{
			Index: gnode.Index(),
			// TODO: support object access paths
			ObjectPath: "",
		}
	case *dataflow.FreeVarNode:
		return summaries.FreeVarSNode{
			Name:       gnode.SsaNode().Name(),
			ObjectPath: "",
		}
	default:
		// Not a node that could be in a summary
		return nil
	}
}

// ToDetailedSummary converts to a detailed summary using the string representation of the nodes instead of the
// graph nodes themselves
func (c ClosedInterproceduralSummary) ToDetailedSummary() (summaries.DetailedSummary, error) {
	flows := map[summaries.SummaryNode][]summaries.SummaryNode{}
	for a, aFlows := range c.Flows {
		as := summaryNodeOfGraphNode(a)
		if as == nil {
			return summaries.DetailedSummary{}, fmt.Errorf("failed to convert graph node to summary node: %v", a)
		}
		for _, b := range aFlows {
			bs := summaryNodeOfGraphNode(b)
			if bs == nil {
				return summaries.DetailedSummary{}, fmt.Errorf("failed to convert graph node to summary node: %v", b)
			}
			flows[as] = append(flows[as], bs)
		}
	}

	return summaries.DetailedSummary{
		Flows:   flows,
		Mutates: make([]summaries.SummaryNode, 0),
	}, nil
}

// ComputeClosedSummary computes the transitively closed summary for function f.
// This uses both the intra- and inter-procedural data flow analyses.
func ComputeClosedSummary(
	ctx context.Context,
	s *dataflow.State,
	f *ssa.Function,
) (ClosedInterproceduralSummary, error) {
	if len(s.FlowGraph.Summaries) == 0 {
		return ClosedInterproceduralSummary{}, fmt.Errorf("data flow state is not initialized")
	}
	s.FlowGraph.Sync()

	graph, ok := s.FlowGraph.Summaries[f]
	if !ok {
		return ClosedInterproceduralSummary{}, fmt.Errorf("failed to find summary for function %s", f)
	}
	if !graph.Constructed || graph.IsInterfaceContract || graph.IsPreSummarized {
		graph = dataflow.NewSummaryGraph(s, f, dataflow.GetUniqueFunctionID(), nil, nil)
		graph.IsInterfaceContract = false
		graph.IsPreSummarized = false
		graph.Constructed = false
		_, err := dataflow.RunIntraProcedural(ctx, s, graph)
		if err != nil {
			return ClosedInterproceduralSummary{},
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
		return ClosedInterproceduralSummary{}, fmt.Errorf(
			"failed to run the inter-procedural data flow analysis: %w",
			errors.Join(errs...))
	}

	for fn, completeSummary := range s.FlowGraph.Summaries {
		if fn == f {
			res := ClosedInterproceduralSummary{Graph: completeSummary, Flows: flows}
			// Even if a global node isn't explicitly visited, it may still be in the summary
			if len(completeSummary.AccessGlobalNodes) > 0 {
				return res, fmt.Errorf("invalid summary: %w", dataflow.ErrGlobal)
			}
			return res, nil
		}
	}

	panic("failed to find computed summary in graph")
}
