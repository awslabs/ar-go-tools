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
	"fmt"
	"slices"
	"time"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
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

// CheckSummary checks the soundness of inferred summary want.
//
// If checkCallees is true, then it infers summaries for the callees that satisfies the
// must-not-flow edges of summary and checks the soundness of these summaries recursively.
func CheckSummary(
	ctx context.Context, s *dataflow.State, want summaries.FrontendDataflowSummary,
	via Method, checkCallees bool,
) (SoundnessResult, error) {
	f, err := functionOfSummary(s, want)
	if err != nil {
		return SoundnessResult{},
			fmt.Errorf("failed to find function of summary %s: %v", want.Name(), err)
	}

	return checkSummary(ctx, s, f, want.Summary(), via, checkCallees)
}

func checkSummary(
	ctx context.Context, s *dataflow.State, f *ssa.Function,
	want summaries.DetailedSummary, via Method, checkCallees bool,
) (SoundnessResult, error) {
	start := time.Now()
	// If callees do not need to be checked, then the most-general and types analyses do not require
	// the intra-procedural data flow results
	if !checkCallees {
		switch via {
		case General:
			return checkSummaryMostGeneral(f, want, start, false)
		case Types:
			return checkSummaryMostGeneral(f, want, start, true)
		}
	}

	summ, ok := s.FlowGraph.Summaries[f]
	if !ok {
		summ = dataflow.NewSummaryGraph(s, f, dataflow.GetUniqueFunctionID(), nil, nil)
		s.FlowGraph.Summaries[f] = summ
	}

	if !summ.Constructed || summ.IsInterfaceContract || summ.IsPreSummarized {
		if _, err := dataflow.RunIntraProcedural(ctx, s, summ); err != nil {
			return SoundnessResult{},
				fmt.Errorf("failed to run intra-procedural analysis for function %s: %v",
					summ.Parent, err)
		}
	}

	// TODO implement other methods
	var res SoundnessResult
	var err error
	switch via {
	case General:
		res, err = checkSummaryMostGeneral(summ.Parent, want, start, false)
	case Types:
		res, err = checkSummaryMostGeneral(summ.Parent, want, start, true)
	case Immutability:
		res, err = checkSummaryImmutability(ctx, s, summ, want, start)
	case Naive:
		res, err = checkSummaryNaive(ctx, s, summ.Parent, want, start)
	default:
		return SoundnessResult{}, fmt.Errorf("unsupported soundness checking method: %v", via)
	}
	if err != nil {
		return res, err
	}

	if !checkCallees || res.IsSound {
		return res, nil
	}

	calleeSummaries, err := inferCalleeSummaries(s, summ, want, via)
	if err != nil {
		return res, fmt.Errorf("failed to infer callee summaries: %v", err)
	}
	for calleeG, calleeSumms := range calleeSummaries {
		isSound := false
		// Only one of the potential callee summaries needs to be sound
		for _, calleeSumm := range calleeSumms {
			// Recursively check the soundness of the callee's inferred summary
			callee := calleeG.Parent
			calleeRes, err := checkSummary(ctx, s, callee, calleeSumm, via, checkCallees)
			if err != nil {
				s.Logger.Errorf("failed to check callee summary: %v", err)
				continue
			}

			s.Logger.Tracef("callee check result: %v", calleeRes)
			if calleeRes.IsSound {
				if len(calleeRes.BadFlows) > 0 {
					panic(fmt.Errorf("want no bad flows in callee %s summary, got: %v",
						callee, calleeRes.BadFlows))
				}
				isSound = true
				break
			}
			res.BadFlows = append(res.BadFlows, calleeRes.BadFlows...)
		}

		// If none of the inferred callee summaries are sound, don't bother checking the rest of the
		// callees in the function
		if !isSound {
			res.IsSound = false
			return res, nil
		}
	}

	return res, nil
}

// isSummarySubset returns true if the edges in got is a subset of the edges in want.
// If not, it also returns the edges in got that are not in want.
func isSummarySubset(
	fn string, want summaries.DetailedSummary, got summaries.DetailedSummary,
) (bool, []Flow) {
	var wantFlows []Flow
	for wfrom, wtos := range want.Flows {
		for _, wto := range wtos {
			wantFlows = append(wantFlows, Flow{Fn: fn, From: wfrom, To: wto})
		}
	}
	var gotFlows []Flow
	for gfrom, gtos := range got.Flows {
		for _, gto := range gtos {
			gotFlows = append(gotFlows, Flow{Fn: fn, From: gfrom, To: gto})
		}
	}

	var diff []Flow
	for _, gflow := range gotFlows {
		if !slices.Contains(wantFlows, gflow) {
			diff = append(diff, gflow)
		}
	}

	return len(diff) == 0, diff
}

func isBadFlow(s *dataflow.State, flow Flow, via Method) bool {
	switch via {
	// General and Types analyses cannot disprove bad flows:
	// if there are any bad flows, the summary is unsound
	case General, Types:
		return true
	case Immutability:
		return isBadFlowImmutability(s, flow)
	default:
		panic("not implemented")
	}
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
