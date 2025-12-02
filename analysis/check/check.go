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
	"time"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// Method determines how the tool checks soundness.
type Method string

const (
	// General means compare with the most-general summary.
	General Method = "general"
	// Types means use the type signature of the function to filter some impossible data flows.
	Types Method = "types"
	// Immutability means use the immutability analysis
	Immutability Method = "immutability"
	// All means use all available analyses in the most efficient way
	All Method = "all"
	// Naive means use the full data flow analysis
	Naive Method = "naive"
)

// CheckSummary checks the soundness of summary.
func CheckSummary(ctx context.Context, s *dataflow.State, summary summaries.FrontendDataflowSummary, via Method) (SoundnessResult, error) {
	start := time.Now()
	// TODO implement other methods
	switch via {
	case Naive:
		return checkSummaryNaive(ctx, s, summary, start)
	case General:
		return checkSummaryMostGeneral(s, summary, start, false)
	case Types:
		return checkSummaryMostGeneral(s, summary, start, true)
	case Immutability:
		return checkSummaryImmutability(ctx, s, summary, start)
	default:
		return SoundnessResult{}, fmt.Errorf("unsupported soundness checking method: %v", via)
	}
}

func checkSummaryImmutability(ctx context.Context, s *dataflow.State, summary summaries.FrontendDataflowSummary, start time.Time) (SoundnessResult, error) {
	f, err := functionOfSummary(s, summary)
	if err != nil {
		return SoundnessResult{}, fmt.Errorf("failed to find function of summary %s: %v", summary.Name(), err)
	}

	summ, ok := s.FlowGraph.Summaries[f]
	if !ok {
		return SoundnessResult{}, fmt.Errorf("summary has not been created for function %s", f)
	}

	if !summ.Constructed {
		if _, err := dataflow.RunIntraProcedural(ctx, s, summ); err != nil {
			return SoundnessResult{},
				fmt.Errorf("failed to run intra-procedural analysis for function %s: %v", summ.Parent, err)
		}
	}

	edges := findSubspecs(s, summ, summary)
	fmt.Println(edges)
	return SoundnessResult{}, nil
}

func checkSummaryNaive(ctx context.Context, s *dataflow.State, summary summaries.FrontendDataflowSummary, start time.Time) (SoundnessResult, error) {
	f, err := functionOfSummary(s, summary)
	if err != nil {
		return SoundnessResult{}, fmt.Errorf("failed to find function of summary %s: %v", summary.Name(), err)
	}

	gotSummary, err := FullySummarize(ctx, s, f)
	if err != nil {
		return SoundnessResult{Time: time.Since(start)}, fmt.Errorf("failed to fully summarize function %s: %w", f.RelString(nil), err)
	}

	got := newDetailedSummary(gotSummary.Flows)
	return SoundnessResult{
		Name:     f.String(),
		Want:     summary,
		Got:      got,
		GotGraph: gotSummary.Graph,
		IsSound:  false,
		Time:     time.Since(start),
	}, nil
}

// checkSummaryMostGeneral checks the soundness of summary by comparing it to the most-general summary.
// The most-general summary assumes that all function inputs (parameters) flow to all function
// outputs (parameters and all return values).
// If useTypes is true, then non-pointer-like inputs are not considered to be outputs.
func checkSummaryMostGeneral(s *dataflow.State, summary summaries.FrontendDataflowSummary, start time.Time, useTypes bool) (SoundnessResult, error) {
	f, err := functionOfSummary(s, summary)
	if err != nil {
		return SoundnessResult{}, fmt.Errorf("failed to find function of summary %s: %v", summary.Name(), err)
	}

	return SoundnessResult{
		Name:     f.String(),
		Want:     summary,
		Got:      newMostGeneralDetailedSummary(f, useTypes),
		GotGraph: nil,
		IsSound:  false,
		Time:     time.Since(start),
	}, nil
}

// newMostGeneralDetailedSummary returns the most-general summary for f.
// If useTypes is true, then non-pointer-like inputs are not treated as outputs.
// TODO include free variables as inputs and outputs
func newMostGeneralDetailedSummary(f *ssa.Function, useTypes bool) summaries.DetailedSummary {
	flows := make(map[summaries.SummaryNode][]summaries.SummaryNode)
	for i, input := range f.Params {
		inputNode := summaries.ArgumentSNode{Name: input.Name(), Index: i, ObjectPath: ""}
		for j, output := range f.Params {
			// We don't count self-flows (input flows to same input as an output) because the data
			// flows to and from the parameter when used as an argument at a callsite are part of
			// the data flow of the caller's summary, not the callee's.
			if input == output {
				continue
			}
			// If the types-based analysis is on, then only pointer-like parameters can be outputs
			if useTypes && !pointer.CanPoint(output.Type()) {
				continue
			}
			outputNode := summaries.ArgumentSNode{Name: output.Name(), Index: j, ObjectPath: ""}
			flows[inputNode] = append(flows[inputNode], outputNode)
		}
		outputs := f.Signature.Results()
		for i := range outputs.Len() {
			outputNode := summaries.ReturnSNode{Index: i, ObjectPath: ""}
			flows[inputNode] = append(flows[inputNode], outputNode)
		}
	}

	return summaries.DetailedSummary{Flows: flows}
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

	graph := dataflow.NewSummaryGraph(s, f, dataflow.GetUniqueFunctionID(), nil, nil)
	graph.IsInterfaceContract = false
	graph.IsPreSummarized = false
	graph.Constructed = false
	_, err := dataflow.RunIntraProcedural(ctx, s, graph)
	if err != nil {
		return FullSummary{}, fmt.Errorf("failed to run intra-procedural data flow analysis: %v", err)
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

func newDetailedSummary(flows map[dataflow.GraphNode][]dataflow.GraphNode) summaries.DetailedSummary {
	res := make(map[summaries.SummaryNode][]summaries.SummaryNode)
	for input, outputs := range flows {
		resInput := newSummaryNode(input)
		var resOutputs []summaries.SummaryNode
		for _, output := range outputs {
			resOutputs = append(resOutputs, newSummaryNode(output))
		}
		res[resInput] = resOutputs
	}

	return summaries.DetailedSummary{Flows: res}
}

// newSummaryNode constructs a summary node from a data flow graph node.
// Panics if gn is invalid since this should be enforced by the visitor.
func newSummaryNode(gn dataflow.GraphNode) summaries.SummaryNode {
	switch gn := gn.(type) {
	case *dataflow.ParamNode:
		f := gn.SsaNode().Parent()
		if recv := f.Signature.Recv(); recv != nil {
			// f is a method and param is a receiver
			return summaries.ArgumentSNode{Name: gn.SsaNode().Name(), Index: 0, ObjectPath: ""}
		}
		return summaries.ArgumentSNode{Name: gn.SsaNode().Name(), Index: gn.Index(), ObjectPath: ""}
	case *dataflow.ReturnValNode:
		return summaries.ReturnSNode{Index: gn.Index(), ObjectPath: ""}
	default:
		panic(fmt.Errorf("unexpected graph node type: %v (%T)", gn, gn))
	}
}

// functionOfSummary returns the SSA function that was summarized in summary.
func functionOfSummary(s *dataflow.State, summary summaries.FrontendDataflowSummary) (*ssa.Function, error) {
	_, isInterface := summary.(summaries.IfaceMethodFlowSummary)
	if isInterface {
		return nil, fmt.Errorf("analysis doesn't handle interfaces yet")
	}

	for fn := range s.ReachableFunctions() {
		fname := fn.RelString(nil)
		if fname == summary.Name() {
			return fn, nil
		}
	}

	return nil, fmt.Errorf("could not find function (is it spelled correctly and reachable from main?)")
}

// InitializeState adds dummy summaries to the data flow graph and builds it.
// Run this before any another method.
func InitializeState(s *dataflow.State) {
	summaries.UnsetStdLibSummaries()                              // HACK removes pre-summarized standard library functions
	s.DataFlowContracts = make(map[string]*dataflow.SummaryGraph) // reset data flow contracts
	fg := dataflow.NewInterProceduralFlowGraph(map[*ssa.Function]*dataflow.SummaryGraph{}, s)
	if len(s.ReachableFunctions()) == 0 {
		panic("no reachable functions")
	}
	for fn := range s.ReachableFunctions() {
		fg.Summaries[fn] = dataflow.NewSummaryGraph(s, fn, dataflow.GetUniqueFunctionID(), nil, nil)
	}
	*s.FlowGraph = fg
	s.FlowGraph.BuildGraph()
}
