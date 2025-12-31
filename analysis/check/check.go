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
	// Recursive means we had to generate the intra-procedural summary and then analyze the functions
	Recursive Method = "recursive"
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
//
// The boolean returned by the function indicates whether the function was found and is reachable.
// If it is not found nor reachable, checking soundness is meaningless: the summary is not a threat to the soundness
// of the dataflow analysis since it will not be used in the same context by the dataflow analysis.
func CheckSummary(
	ctx context.Context,
	s *State,
	want summaries.FrontendDataflowSummary,
	specs []dataflow.ScanningSpec,
) (SoundnessResult, bool, error) {
	f, err := functionOfName(s, want.Name())
	if err != nil {
		return SoundnessResult{},
			false, fmt.Errorf("failed to find function of summary %s: %v", want.Name(), err)
	}

	res, err := checkSummary(ctx, s, f, want.Summary(), specs)
	return res, true, err
}

var errInfer = errors.New("failed to infer callee summaries")

// checkSummary checks the soundness of the given data flow summary for f in want.
//
// General takes want and returns all must-not-flows it couldn't prove.
// Each analysis method takes a set of must-not-flows it needs to prove, and returns the set of
// must-not-flows it wasn't able to prove.
// Try general, then types, then immutability, etc.
// Each method removes more must-not-flows, which makes the next task easier.
//
//gocyclo:ignore
func checkSummary(
	ctx context.Context, s *State, f *ssa.Function, want summaries.DetailedSummary,
	specs []dataflow.ScanningSpec,
) (SoundnessResult, error) {
	g := dataflow.NewSummaryGraph(s.State, f, dataflow.GetUniqueFunctionID(), nil, nil)
	// Store the newly-created graph in s.FlowGraph.Summaries so it can be referenced later.
	// This way there is only one summary graph created per *ssa.Function
	s.FlowGraph.Summaries[f] = g

	// Different sub-analyses may have different soundness requirements.
	// Find all of the unsound features at once and then check them on a per-analysis basis.
	unsoundCheckFeats := findUnsoundCheckFeatures(s, f, specs)

	start := time.Now()
	soundnessResultBase := SoundnessResult{
		Fn:      f,
		Name:    f.RelString(nil),
		Want:    want,
		IsSound: true,
		Time:    time.Duration(0),
	}
	var unprovenMustNotFlows []flow
	var method Method
	for _, m := range []Method{General, Types, Immutability} {
		method = m
		var soundnessResult SoundnessResult
		var done bool
		var err error
		switch method {
		case General:
			unprovenMustNotFlows, soundnessResult, done, err = checkMethodGeneral(
				s, f, unsoundCheckFeats, soundnessResultBase, g, want, start)
			if done {
				return soundnessResult, err
			}
		case Types:
			unprovenMustNotFlows, soundnessResult, done, err = checkMethodTypes(
				s, f, unsoundCheckFeats, soundnessResultBase, unprovenMustNotFlows, start)
			if done {
				return soundnessResult, err
			}
		case Immutability:
			unprovenMustNotFlows, soundnessResult, done, err = checkMethodImmutability(
				ctx, s, f, unsoundCheckFeats, soundnessResultBase, unprovenMustNotFlows, start)
			if done {
				return soundnessResult, err
			}
		}

		if len(unprovenMustNotFlows) == 0 {
			s.Logger.Debugf(
				"no unproven must-not-flows from checking function %s via method %s: done checking\n",
				f, method)
			soundnessResultBase.IsSound = unsoundCheckFeats.isSound()
			soundnessResultBase.Unsoundness = Unsoundness{
				UnprovenMustNotFlows: nil,
				CheckFeatures:        unsoundCheckFeats,
			}
			soundnessResultBase.Method = method
			soundnessResultBase.Time = time.Since(start)
			return soundnessResultBase, nil
		}

		if s.Logger.LogsDebug() {
			s.Logger.Debugf(
				"unproven must-not-flows from checking function %s via method %s:\n", f, method)
			for _, fl := range unprovenMustNotFlows {
				s.Logger.Debugf("\t%v\n", fl)
			}
		}
	}

	s.Logger.Debugf("inferring callee summaries for function %s...\n", f)
	unsoundness := Unsoundness{
		UnprovenMustNotFlows: funcutil.Map(unprovenMustNotFlows, newFlow),
		CheckFeatures:        unsoundCheckFeats,
	}
	// Use the type analysis to filter out unrealizable flows
	calleeSummaries, err := inferCalleeSummaries(
		ctx, s.State, g, unprovenMustNotFlows, &unsoundness, Types)
	if err != nil {
		soundnessResultBase.IsSound = false
		soundnessResultBase.Unsoundness = unsoundness
		soundnessResultBase.Time = time.Since(start)
		soundnessResultBase.Method = Recursive
		return soundnessResultBase, fmt.Errorf("%w for %s: %v", errInfer, f, err)
	}
	if len(calleeSummaries) == 0 {
		s.Logger.Tracef("no callee results for function %s: done analyzing\n", f)
		if unsoundness.isSound() {
			unsoundness.UnprovenMustNotFlows = nil
		}
		soundnessResultBase.IsSound = unsoundness.isSound()
		soundnessResultBase.Unsoundness = unsoundness
		soundnessResultBase.Time = time.Since(start)
		soundnessResultBase.Method = method // The algorithm didn't have to recurse here.
		return soundnessResultBase, nil
	}

	// Since we inferred callee summaries, we have intra-procedural results for f.
	// This means that we only need to prove the must-not-flows in the callees.
	calleeResults, soundnessResult, done, err2 := checkCalleeSummaries(ctx, s, f,
		calleeSummaries, specs, soundnessResultBase, unsoundness, start)
	if done {
		return soundnessResult, err2
	}

	// If all inferred callee summaries are sound, then the summary for f is sound.
	calleesSound := true
	for _, crs := range calleeResults {
		// Only one inferred callee summary needs to be sound.
		calleeSound := false
		for _, cr := range crs {
			if cr.IsSound {
				calleeSound = true
				break
			}
		}
		if !calleeSound {
			calleesSound = false
			break
		}
	}
	if calleesSound {
		unsoundness.UnprovenMustNotFlows = nil
	}

	// TODO Filter out must-not-flows that are proven via checking the callees
	return SoundnessResult{
		Fn:            f,
		Name:          f.RelString(nil),
		Want:          want,
		IsSound:       calleesSound,
		Unsoundness:   unsoundness,
		Method:        Recursive,
		Time:          time.Since(start),
		CalleeResults: calleeResults,
	}, nil
}

func checkCalleeSummaries(ctx context.Context, s *State, f *ssa.Function,
	calleeSummaries map[*ssa.Function][]summaries.DetailedSummary,
	specs []dataflow.ScanningSpec,
	soundnessResultBase SoundnessResult,
	unsoundness Unsoundness,
	start time.Time) ([][]SoundnessResult, SoundnessResult, bool, error) {
	var calleeResults [][]SoundnessResult
	for callee, calleeSumms := range calleeSummaries {
		if len(calleeSumms) == 0 {
			// If there are no callee summaries inferred, this is a bug.
			panic(fmt.Errorf("no summaries inferred for callee: %s", callee))
		}

		var thisCalleeResults []SoundnessResult
		for _, calleeSumm := range calleeSumms {
			// Recursively check the soundness of the callee's inferred summary
			s.Logger.Tracef(
				"checking inferred summary for callee %s in %s: %v\n", callee, f, calleeSumm)
			calleeRes, err := checkSummary(ctx, s, callee, calleeSumm, specs)
			if err != nil {
				s.Logger.Errorf("failed to check callee summary: %v", err)
				if errors.Is(err, errInfer) {
					// If callee summary inference failed, then the result is unsound because
					// the inferred summaries are incomplete/incorrect.
					// Return the must-not-flows for the caller plus any successfully analyzed
					// callees.
					soundnessResultBase.IsSound = false
					soundnessResultBase.Unsoundness = unsoundness
					soundnessResultBase.CalleeResults = append(calleeResults, thisCalleeResults)
					soundnessResultBase.Time = time.Since(start)
					soundnessResultBase.Method = calleeRes.Method
					return nil, soundnessResultBase, true, nil
				}
				continue
			}
			thisCalleeResults = append(thisCalleeResults, calleeRes)

			s.Logger.Tracef("callee check result: %+v", calleeRes)
			// Only one of the potential callee summaries needs to be sound.
			// NOTE This is disabled for now to make tests deterministic.
			// if calleeRes.IsSound {
			// 	if len(calleeRes.UnprovenMustNotFlows) > 0 {
			// 		panic(fmt.Errorf(
			// 			"want no unproven must-not-flows in callee %s summary, got: %v",
			// 			callee, calleeRes.UnprovenMustNotFlows))
			// 	}
			// 	break
			// }
		}

		calleeResults = append(calleeResults, thisCalleeResults)
	}
	return calleeResults, SoundnessResult{}, false, nil
}

func checkMethodImmutability(ctx context.Context, s *State, f *ssa.Function,
	unsoundCheckFeats UnsoundCheckFeatures,
	soundnessResultBase SoundnessResult,
	unprovenMustNotFlows []flow,
	start time.Time) ([]flow, SoundnessResult, bool, error) {
	// The immutability analysis is unsound if there is reflection, as it depends on the
	// pointer analysis.
	if len(unsoundCheckFeats.ReflectUsages) > 0 {
		s.Logger.Warnf(
			"immutability analysis is unsound: detected reflection use in function %s\n", f)
		if !s.Config.CheckIgnoresUnsound {
			soundnessResultBase.IsSound = false
			soundnessResultBase.Unsoundness = Unsoundness{
				UnprovenMustNotFlows: funcutil.Map(unprovenMustNotFlows, newFlow),
				CheckFeatures:        unsoundCheckFeats,
			}
			soundnessResultBase.Method = Immutability
			soundnessResultBase.Time = time.Since(start)
			return nil, soundnessResultBase, true, nil
		}
	}
	unprovenMustNotFlows = filterFlowsImmutability(ctx, s, unprovenMustNotFlows)
	return unprovenMustNotFlows, SoundnessResult{}, false, nil
}

func checkMethodTypes(s *State, f *ssa.Function,
	unsoundCheckFeats UnsoundCheckFeatures,
	soundnessResultBase SoundnessResult,
	unprovenMustNotFlows []flow,
	start time.Time) ([]flow, SoundnessResult, bool, error) {
	// The types analysis is unsound if there is unsafe, as unsafe memory operations can
	// induce data flow to non-pointer-like summary nodes.
	if len(unsoundCheckFeats.UnsafeUsages) > 0 {
		s.Logger.Warnf(
			"types analysis is unsound: detected unsafe use in function %s\n", f)
		if !s.Config.CheckIgnoresUnsound {
			soundnessResultBase.IsSound = false
			soundnessResultBase.Unsoundness = Unsoundness{
				UnprovenMustNotFlows: funcutil.Map(unprovenMustNotFlows, newFlow),
				CheckFeatures:        unsoundCheckFeats,
			}
			soundnessResultBase.Time = time.Since(start)
			soundnessResultBase.Method = Types
			return nil, soundnessResultBase, true, nil
		}
	}
	unprovenMustNotFlows = filterFlowsTypes(unprovenMustNotFlows)
	return unprovenMustNotFlows, SoundnessResult{}, false, nil
}

func checkMethodGeneral(s *State, f *ssa.Function,
	unsoundCheckFeats UnsoundCheckFeatures,
	soundnessResultBase SoundnessResult,
	g *dataflow.SummaryGraph,
	want summaries.DetailedSummary,
	start time.Time) ([]flow, SoundnessResult, bool, error) {
	wantFlows, err := summaryFlows(g, want)
	if err != nil {
		soundnessResultBase.IsSound = false
		soundnessResultBase.Unsoundness = Unsoundness{
			UnprovenMustNotFlows: []Flow{},
			BadForm:              err,
			CheckFeatures:        unsoundCheckFeats,
		}
		soundnessResultBase.Method = General
		soundnessResultBase.Time = time.Since(start)
		return nil, soundnessResultBase, true, nil
	}
	// The most-general summary is unsound if there are any globals (as we do not have
	// special global nodes in summaries yet).
	if len(unsoundCheckFeats.GlobalUsages) > 0 {
		s.Logger.Warnf(
			"most-general summary is unsound: detected global use in function %s (%s)\n",
			f, s.Program.Fset.Position(f.Pos()))
		if !s.Config.CheckIgnoresUnsound {
			soundnessResultBase.IsSound = false
			soundnessResultBase.Unsoundness = Unsoundness{CheckFeatures: unsoundCheckFeats}
			soundnessResultBase.Method = General
			return nil, soundnessResultBase, true, nil
		}
	}
	unprovenMustNotFlows := checkSummaryMostGeneral(g, wantFlows)
	return unprovenMustNotFlows, SoundnessResult{}, false, nil
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

// functionOfName returns the SSA function that has name and that is reachable.
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
