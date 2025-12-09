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
	"time"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
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

// State is the state of the analysis.
type State struct {
	*dataflow.State
	cache         *aliasCache
	immutableVals map[ssa.Value]struct{}
}

// NewState returns a State from an initialized (but not built!) dataflow analysis state.
// Make sure this is called in isolation from any dataflow analyses because it removes
// the pre-summarized standard library functions.
func NewState(s *dataflow.State) result.Result[State] {
	fg := dataflow.NewInterProceduralFlowGraph(map[*ssa.Function]*dataflow.SummaryGraph{}, s)
	if len(s.ReachableFunctions()) == 0 {
		panic("no reachable functions")
	}
	for fn := range s.ReachableFunctions() {
		fg.Summaries[fn] = dataflow.NewSummaryGraph(
			s, fn, dataflow.GetUniqueFunctionID(), nil, nil)
	}
	*s.FlowGraph = fg
	s.FlowGraph.BuildGraph()

	res := &State{
		State: s,
		cache: &aliasCache{
			ptrRes:         s.PointerAnalysis,
			objectPointees: make(map[ssa.Value]map[*pointer.Object]struct{}),
		},
		immutableVals: make(map[ssa.Value]struct{}),
	}
	return result.Ok(res)
}

// CheckSummary checks the soundness of inferred summary want.
//
// If checkCallees is true, then it infers summaries for the callees that satisfies the
// must-not-flow edges of summary and checks the soundness of these summaries recursively.
func CheckSummary(
	ctx context.Context, s *State, want summaries.FrontendDataflowSummary,
) (SoundnessResult, error) {
	f, err := functionOfName(s, want.Name())
	if err != nil {
		return SoundnessResult{},
			fmt.Errorf("failed to find function of summary %s: %v", want.Name(), err)
	}

	return checkSummary(ctx, s, f, want.Summary())
}

func checkSummary(
	ctx context.Context, s *State, f *ssa.Function, want summaries.DetailedSummary,
) (SoundnessResult, error) {
	// General takes want and returns all flows it couldn't disprove.
	// Each analysis method takes a set of flows it needs to disprove, and returns the set of flows it wasn't able to disprove.
	// Try general, then types, then immutability, etc.
	// Each method disproves more flows, which makes the next task easier.

	g, ok := s.FlowGraph.Summaries[f]
	if !ok {
		g = dataflow.NewSummaryGraph(s.State, f, dataflow.GetUniqueFunctionID(), nil, nil)
	}

	start := time.Now()
	var res checkResult
	for _, method := range []Method{General, Types, Immutability} {
		switch method {
		case General:
			res = checkSummaryMostGeneral(g, want)
		case Types:
			res = checkSummaryTypes(res.badFlows)
		case Immutability:
			res = checkSummaryImmutability(s, res.badFlows)
		}

		if res.isSound {
			return newSoundnessResult(g, res, want, start, method), nil
		}
	}

	// Check callee summaries
	// Use the type analysis to filter out unrealizable flows
	calleeSummaries, err := inferCalleeSummaries(ctx, s.State, g, want, Types)
	if err != nil {
		return SoundnessResult{}, fmt.Errorf("failed to infer callee summaries: %v", err)
	}
	if len(calleeSummaries) == 0 {
		return newSoundnessResult(g, res, want, start, Types), nil
	}

	var badFlows []Flow
	var method Method
	for calleeG, calleeSumms := range calleeSummaries {
		if len(calleeSumms) == 0 {
			return SoundnessResult{},
				fmt.Errorf("no summaries inferred for callee: %s", calleeG.Parent)
		}
		isSound := false
		// Only one of the potential callee summaries needs to be sound
		for _, calleeSumm := range calleeSumms {
			// Recursively check the soundness of the callee's inferred summary
			callee := calleeG.Parent
			calleeRes, err := checkSummary(ctx, s, callee, calleeSumm)
			method = calleeRes.Method
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
			badFlows = append(badFlows, calleeRes.BadFlows...)
		}

		// If none of the inferred callee summaries are sound, don't bother checking the rest of the
		// callees in the function
		if !isSound {
			return SoundnessResult{
				Fn:       f.RelString(nil),
				Want:     want,
				IsSound:  false,
				BadFlows: append(funcutil.Map(res.badFlows, newFlow), badFlows...),
				Method:   method,
			}, nil
		}
	}

	result := newSoundnessResult(g, res, want, start, method)
	result.BadFlows = badFlows
	result.IsSound = len(badFlows) == 0

	return result, nil
}

// checkResult is the result of a soundness sub-check.
type checkResult struct {
	// isSound is true if the summary is sound (all bad flows were proven to not hold).
	isSound bool
	// badFlows are all the flows that were not able to be disproven by the analysis.
	badFlows []flow
	// method is the method used to perform the check.
	method Method
}

func newCheckResult(unproven []flow, via Method) checkResult {
	return checkResult{isSound: len(unproven) == 0, badFlows: unproven, method: via}
}

// flow is a potential data flow.
type flow struct {
	from dataflow.GraphNode
	to   dataflow.GraphNode
}

func (f flow) String() string {
	return fmt.Sprintf("%s -> %s", f.from, f.to)
}

// difference returns the elements of a that are not in b.
func difference(a, b []flow) []flow {
	mb := make(map[flow]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []flow
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}

	return diff
}

// functionOfName returns the SSA function that has name.
func functionOfName(s *State, name string) (*ssa.Function, error) {
	for fn := range s.ReachableFunctions() {
		fname := fn.RelString(nil)
		if fname == name {
			return fn, nil
		}
	}

	return nil, fmt.Errorf(
		"could not find function (is it spelled correctly and reachable from main?)")
}
