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
	"slices"
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

var errInfer = errors.New("failed to infer callee summaries")

// checkSummary checks the soundness of the given data flow summary for f in want.
//
// General takes want and returns all must-not-flows it couldn't prove.
// Each analysis method takes a set of must-not-flows it needs to prove, and returns the set of
// must-not-flows it wasn't able to prove.
// Try general, then types, then immutability, etc.
// Each method removes more must-not-flows, which makes the next task easier.
func checkSummary(
	ctx context.Context, s *State, f *ssa.Function, want summaries.DetailedSummary,
) (SoundnessResult, error) {
	g := dataflow.NewSummaryGraph(s.State, f, dataflow.GetUniqueFunctionID(), nil, nil)
	// Store the newly-created graph in s.FlowGraph.Summaries so it can be referenced later.
	// This way there is only one summary graph created per *ssa.Function
	s.FlowGraph.Summaries[f] = g

	start := time.Now()
	var res checkResult
	var method Method
	for _, meth := range []Method{General, Types, Immutability} {
		switch meth {
		case General:
			res = checkSummaryMostGeneral(g, want)
		case Types:
			res = checkSummaryTypes(res.mustNotFlows)
		case Immutability:
			res = checkSummaryImmutability(ctx, s, res.mustNotFlows)
		}

		if s.Logger.LogsDebug() {
			s.Logger.Debugf(
				"unproven must-not-flows from checking function %s via method %s:\n", f, meth)
			for _, fl := range res.mustNotFlows {
				s.Logger.Debugf("\t%v\n", fl)
			}
		}

		if res.isSound {
			return newSoundnessResult(g, res, want, start, meth), nil
		}
		method = meth
	}
	topMustNotFlows := funcutil.Map(res.mustNotFlows, newFlow)

	// Check callee summaries
	// Use the type analysis to filter out unrealizable flows
	s.Logger.Tracef("inferring callee summaries for function %s...\n", f)
	calleeSummaries, err := inferCalleeSummaries(ctx, s.State, g, res.mustNotFlows, Types)
	if err != nil {
		return SoundnessResult{
			Fn:                   f.RelString(nil),
			Want:                 want,
			IsSound:              false,
			UnprovenMustNotFlows: topMustNotFlows,
			Method:               method,
			Time:                 time.Since(start),
		}, fmt.Errorf("%w for %s: %v", errInfer, f, err)
	}
	if len(calleeSummaries) == 0 {
		return newSoundnessResult(g, res, want, start, method), nil
	}

	// Since we inferred callee summaries, we have intra-procedural results for f.
	// This means that we only need to prove the must-not-flows in the callees.
	var calleeMustNotFlows []Flow
	for calleeG, calleeSumms := range calleeSummaries {
		if len(calleeSumms) == 0 {
			return SoundnessResult{},
				fmt.Errorf("no summaries inferred for callee: %s", calleeG.Parent)
		}
		// Only one of the potential callee summaries needs to be sound
		// isSound := false // NOTE temporarily disabled: see note below
		for _, calleeSumm := range calleeSumms {
			// Recursively check the soundness of the callee's inferred summary
			callee := calleeG.Parent
			s.Logger.Tracef(
				"checking inferred summary for callee %s in %s: %v\n", callee, f, calleeSumm)
			calleeRes, err := checkSummary(ctx, s, callee, calleeSumm)
			for _, fl := range calleeRes.UnprovenMustNotFlows {
				// Callee must-not-flows should be relatively small so even though this is a linear
				// scan, it should be faster than enforcing uniqueness via a map.
				if !slices.Contains(calleeMustNotFlows, fl) {
					calleeMustNotFlows = append(calleeMustNotFlows, fl)
				}
			}
			if err != nil {
				s.Logger.Errorf("failed to check callee summary: %v", err)
				if errors.Is(err, errInfer) {
					// If callee summary inference failed, then the result is unsound because
					// the inferred summaries are incomplete/incorrect.
					// Return the must-not-flows for the caller plus any successfully analyzed
					// callees.
					return SoundnessResult{
						Fn:                   f.RelString(nil),
						Want:                 want,
						IsSound:              false,
						UnprovenMustNotFlows: append(topMustNotFlows, calleeMustNotFlows...),
						Method:               method,
						Time:                 time.Since(start),
					}, nil
				}
				method = calleeRes.Method
				continue
			}

			s.Logger.Tracef("callee check result: %+v", calleeRes)
			if calleeRes.IsSound {
				if len(calleeRes.UnprovenMustNotFlows) > 0 {
					panic(fmt.Errorf(
						"want no unproven must-not-flows in callee %s summary, got: %v",
						callee, calleeRes.UnprovenMustNotFlows))
				}
				// If this inferred callee summary is sound, don't bother checking the rest of the
				// inferred summaries.
				// isSound = true
				break
			}
		}

		// NOTE This logic is temporarily disabled to make tests with multiple callees more
		// deterministic.
		// It can be re-enabled if reporting all unproven must-not-flows has performance issues.
		//
		// // If none of the inferred callee summaries are sound, don't bother checking the rest of the
		// // callees in the function
		// if !isSound {
		// 	return SoundnessResult{
		// 		Fn:                   f.RelString(nil),
		// 		Want:                 want,
		// 		IsSound:              false,
		// 		UnprovenMustNotFlows: append(topMustNotFlows, calleeMustNotFlows...),
		// 		Method:               method,
		// 		Time:                 time.Since(start),
		// 	}, nil
		// }
	}

	// If there are no callee must-not-flows, then the summary for f is sound.
	isSound := len(calleeMustNotFlows) == 0

	// If the summary is unsound, return the must-not-flows for f as well as any unproven
	// must-not-flows for the callees.
	// TODO This can probably be improved by only returning the must-not-flows for f that are
	// implied by the must-not-flows for the callees.
	unproven := calleeMustNotFlows
	if !isSound {
		unproven = append(topMustNotFlows, unproven...)
	}

	return SoundnessResult{
		Fn:                   f.RelString(nil),
		Want:                 want,
		IsSound:              isSound,
		UnprovenMustNotFlows: unproven,
		Method:               method,
		Time:                 time.Since(start),
	}, nil
}

// checkResult is the result of a soundness sub-check.
type checkResult struct {
	// isSound is true if the summary is sound (all must-not-flows were proven to hold).
	isSound bool
	// mustNotFlows are all the must-not-flows that were not able to be proven by the analysis.
	mustNotFlows []flow
	// method is the method used to perform the check.
	method Method
}

func newCheckResult(mustNotFlows []flow, via Method) checkResult {
	return checkResult{isSound: len(mustNotFlows) == 0, mustNotFlows: mustNotFlows, method: via}
}

// flow is a data flow between two summary graph nodes.
type flow struct {
	from dataflow.GraphNode
	to   dataflow.GraphNode
}

func (f flow) String() string {
	return fmt.Sprintf("%s->%s", graphNodeDesc(f.from), graphNodeDesc(f.to))
}

// difference returns the elements of a that are not in b.
func difference[T comparable](a, b []T) []T {
	mb := make(map[T]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []T
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
