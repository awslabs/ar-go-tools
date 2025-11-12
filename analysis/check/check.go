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
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

// Method determines how the tool checks soundness.
type Method string

const (
	Types        Method = "types"        // Types means use the type analysis
	Immutability Method = "immutability" // Immutability means use the immutability analysis
	All          Method = "all"          // All means use all available analyses in the most efficient way
	Naive        Method = "naive"        // Naive means use the full data flow analysis
)

// CheckSummary checks the soundness of summary.
func CheckSummary(s *dataflow.State, summary summaries.FrontendDataflowSummary, via Method) (SoundnessResult, error) {
	// TODO implement other methods
	switch via {
	case Naive:
		return checkSummaryNaive(s, summary)
	default:
		return SoundnessResult{}, fmt.Errorf("unsupported soundness checking method: %v", via)
	}
}

// FullSummary is the full inter-procedurally-generated data flow summary for a function.
type FullSummary struct {
	Graph *dataflow.SummaryGraph                      // Graph is the summary graph.
	Flows map[dataflow.GraphNode][]dataflow.GraphNode // Flows are from function inputs to outputs.
}

// FullySummarize computes the full data flow summary for function f.
// This uses both the intra- and inter-procedural data flow analyses.
func FullySummarize(s *dataflow.State, f *ssa.Function) (FullSummary, error) {
	if len(s.FlowGraph.Summaries) == 0 {
		return FullSummary{}, fmt.Errorf("data flow state is not initialized")
	}

	graph := dataflow.NewSummaryGraph(s, f, dataflow.GetUniqueFunctionID(), nil, nil)
	graph.IsInterfaceContract = false
	graph.IsPreSummarized = false
	graph.Constructed = false
	_, err := dataflow.RunIntraProcedural(s, graph)
	if err != nil {
		return FullSummary{}, fmt.Errorf("failed to run intra-procedural data flow analysis: %v", err)
	}

	flows := make(map[dataflow.GraphNode][]dataflow.GraphNode)
	for _, param := range graph.Params {
		v := dataflow.NewFuncInputVisitor()
		s.Logger = config.NewLogGroup(&config.Config{
			Options: config.Options{
				LogLevel:    int(config.InfoLevel),
				SilenceWarn: true,
			},
		})
		v.Visit(s, dataflow.NodeWithTrace{Node: param})
		flows[param] = v.Flows()
	}
	if s.Report.HasErrors() {
		errs := s.Report.CheckError()
		return FullSummary{}, fmt.Errorf(
			"failed to run the inter-procedural data flow analysis: %v",
			errors.Join(errs...))
	}
	s.FlowGraph.Sync()

	for fn, completeSummary := range s.FlowGraph.Summaries {
		if fn == f {
			return FullSummary{Graph: completeSummary, Flows: flows}, nil
		}
	}

	panic("failed to find computed summary in graph")
}

func checkSummaryNaive(s *dataflow.State, summary summaries.FrontendDataflowSummary) (SoundnessResult, error) {
	f, err := functionOfSummary(s, summary)
	if err != nil {
		return SoundnessResult{}, fmt.Errorf("failed to find function of summary %s: %v", summary.Name(), err)
	}

	gotSummary, err := FullySummarize(s, f)
	if err != nil {
		return SoundnessResult{}, fmt.Errorf("failed to fully summarize function %s: %v", f.RelString(nil), err)
	}
	got := newDetailedSummary(gotSummary.Flows)

	return SoundnessResult{
		Want:    summary,
		Got:     got,
		IsSound: false,
	}, nil
}

func isOverapproximation(want summaries.Summarizer, got summaries.DetailedSummary) bool {
	panic("TODO")
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
	s.DataFlowContracts = make(map[string]*dataflow.SummaryGraph) // reset data flow contracts
	dataflow.RunIntraProceduralPass(s, runtime.NumCPU(), dataflow.IntraAnalysisParams{
		// Don't build any summaries since we're summarizing on-demand
		ShouldBuildSummary: func(*dataflow.State, *ssa.Function) bool {
			return false
		},
		// No need to track sources, sinks, or synthetic nodes since they don't appear in data flow summaries
		ShouldTrack: func(*dataflow.State, ssa.Node) bool {
			return false
		},
	})
	s.FlowGraph.BuildGraph()
}
