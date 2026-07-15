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
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/lang"
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
	// Read means use the read analysis to filter flow inputs.
	Read Method = "read"
	// Types means use the type signature of the function to filter flow outputs.
	Types Method = "types"
	// Immutability means use the immutability analysis to filter flow outpts.
	Immutability Method = "immutability"
	// Recursive means we had to generate the intra-procedural summary and then analyze the functions.
	Recursive Method = "recursive"
	// All means use all available analyses in the most efficient way.
	All Method = "all"
	// Naive means use the full data flow analysis.
	Naive Method = "naive"
)

// State is the state of the analysis.
type State struct {
	*dataflow.State
	cache         *aliasCache
	immutableVals map[value]struct{}
	unreadVals    map[value]struct{}
}

// value is an SSA value with an access path for field-sensitivity.
type value struct {
	ssa.Value
	pth path
}

// NewState returns a State from an initialized (but not built!) dataflow analysis state.
// Make sure this is called in isolation from any dataflow analyses because it removes
// the pre-summarized standard library functions.
func NewState(s *dataflow.State) result.Result[State] {
	res := &State{
		State: s,
		cache: &aliasCache{
			ptrRes: s.PointerAnalysis,
			labels: make(map[ssa.Value]map[*pointer.Label]struct{}),
		},
		immutableVals: make(map[value]struct{}),
		unreadVals:    make(map[value]struct{}),
	}
	res.PopulateTypesToImplementationMap()
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
//
// If the summary to be checked is the summary of an interface method, then the function returns a list of soundness
// results, one for each possible implementation of the method.
//
// If the summary to be checked is the summary of a function or struct method, then a single soundness result will be
// in the slice of results returned.
func CheckSummary(
	ctx context.Context,
	s *State,
	want summaries.FrontendDataflowSummary,
	specs []dataflow.ScanningSpec,
	testNaive bool,
) ([]SoundnessResult, bool, error) {
	// NOTE Hardcode configs so we don't make unintentional mistakes.
	s.Config.DataflowProblems.CheckIgnoresUnsound = true
	s.Config.DataflowProblems.CheckIgnoresPredefined = false

	// SPECIAL CASE: INTERFACES
	if ifaceSummary, isIfaceSummary := want.(summaries.IfaceMethodFlowSummary); isIfaceSummary {
		// Checking a summary that is for a method of an interface
		// This means we need to gather all the possible implementations, and check every single one.
		implementations := s.ImplementationsByType
		key := lang.MethodKey(ifaceSummary.Package()+"."+ifaceSummary.Interface, ifaceSummary.Method)
		if implems, isPresent := implementations[key]; isPresent {
			var res []SoundnessResult
			for implem := range implems {
				s.Logger.Infof(
					"Checking that interface summary for %s is sound for implementation %s",
					want.Name(), implem.RelString(nil))
				callStack := []*ssa.Function{implem}
				partRes, err := checkSummary(
					ctx, s, implem, want.Summary(), specs, testNaive, callStack)
				res = append(res, partRes)
				if err != nil {
					return res, true, err
				}
			}
			return res, true, nil
		}
		return []SoundnessResult{}, false, fmt.Errorf("failed to find implementations of interface %s", key)
	}
	// CASE: NORMAL FUNCTIONS
	// Checking a summary that is for a single function/method
	f, err := s.FunctionOfName(want.Name())
	if err != nil {
		return []SoundnessResult{},
			false, fmt.Errorf("failed to find function of summary %s: %v", want.Name(), err)
	}

	s.Logger.Infof("checking the soundness of summary %s ...\n", want.Summary())
	callStack := []*ssa.Function{f}
	res, err := checkSummary(ctx, s, f, want.Summary(), specs, testNaive, callStack)
	return []SoundnessResult{res}, true, err
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
// The callStack is used to avoid looping forever when checking the soundness of recursive callees.
//
//gocyclo:ignore
func checkSummary(
	ctx context.Context, s *State, f *ssa.Function, want summaries.DetailedSummary,
	specs []dataflow.ScanningSpec, testNaive bool, callStack []*ssa.Function,
) (SoundnessResult, error) {
	// The checkable summary format has no syntax for a top-level closure's free variables, so
	// reject f if it's a closure -- but only at the outermost call (len(callStack) == 1):
	// recursively-checked callees use an inferred summary, which does support free variables.
	if len(callStack) == 1 && len(f.FreeVars) > 0 {
		return SoundnessResult{Soundness: Error},
			fmt.Errorf("cannot check soundness of %s: it is a closure with free variables, which "+
				"the checkable summary format cannot express for a top-level target", f)
	}

	g := dataflow.NewSummaryGraph(s.State, f, dataflow.GetUniqueFunctionID(), nil, nil)
	// Store the newly-created graph in s.FlowGraph.Summaries so it can be referenced later.
	// This way there is only one summary graph created per *ssa.Function
	s.FlowGraph.Summaries[f] = g

	// Different sub-analyses may have different soundness requirements.
	// Find all of the unsound features at once and then check them on a per-analysis basis.
	s.Logger.Debugf("finding unsound check features of %s ...\n", f)
	unsoundCheckFeats, err := findUnsoundCheckFeatures(ctx, s, f, specs)
	if err != nil {
		err := fmt.Errorf("failed to find unsound check features for %s: %v", f, err)
		s.Logger.Errorf("%s\n", err)
		if !s.Config.CheckIgnoresUnsound {
			return SoundnessResult{Soundness: Error}, err
		}
	}
	s.Logger.Debugf("unsound check features of %s: %+v\n", f, unsoundCheckFeats)

	start := time.Now()
	soundnessResultBase := SoundnessResult{
		Fn:           f,
		Name:         f.RelString(nil),
		Want:         want,
		Soundness:    Sound,
		MethodCounts: map[Method]int{},
		Time:         time.Duration(0),
	}
	var unprovenMustNotFlows []flow
	// Special case if we're testing the "naive" method
	if testNaive {
		_, soundnessResult, _, err := checkMethodNaive(
			ctx, s, unsoundCheckFeats, soundnessResultBase, g, want, start, specs)
		return soundnessResult, err
	}

	var method Method
	wantFlows, err := summaryFlows(s, g, want)
	if err != nil {
		soundnessResultBase.Soundness = Error
		soundnessResultBase.Unsoundness = Unsoundness{
			UnprovenMustNotFlows: []Flow{},
			BadForm:              err,
			CheckFeatures:        unsoundCheckFeats,
		}
		soundnessResultBase.Method = General
		soundnessResultBase.Time = time.Since(start)
		return soundnessResultBase,
			fmt.Errorf("failed to compute summary flows for %v: %v", want, err)
	}

	// Determine the precision we need for the analyses by the length of the access paths in each
	// node in summary flows.
	prec := newPrecisions(wantFlows)
	s.Logger.Debugf("input node path len: %+v\n", prec.inputs.nodePathLen)
	s.Logger.Debugf("ouput node path len: %+v\n", prec.outputs.nodePathLen)

	for _, m := range []Method{General, Types, Immutability, Read} {
		method = m
		var soundnessResult SoundnessResult
		var done bool
		var err error
		beforeCount := len(unprovenMustNotFlows)
		switch method {
		case General:
			unprovenMustNotFlows, soundnessResult, done, err = checkMethodGeneral(
				s, f, unsoundCheckFeats, soundnessResultBase, g, wantFlows, prec)
			if done {
				return soundnessResult, err
			}
			// For General, the initial must-not-flows come from wantFlows minus the actual flows.
			// The "proved" count is the total wantFlows minus what remains unproven.
			beforeCount = len(wantFlows)
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
		case Read:
			unprovenMustNotFlows, soundnessResult, done, err = checkMethodRead(
				ctx, s, f, unsoundCheckFeats, soundnessResultBase, unprovenMustNotFlows, start)
			if done {
				return soundnessResult, err
			}
		}

		if proved := beforeCount - len(unprovenMustNotFlows); proved > 0 {
			soundnessResultBase.MethodCounts[method] = proved
		}

		if err != nil {
			return soundnessResultBase,
				fmt.Errorf("failed to check %s via method %s: %w", f, method, err)
		}

		if len(unprovenMustNotFlows) == 0 {
			s.Logger.Debugf(
				"no unproven must-not-flows from checking function %s via method %s: done checking\n",
				f, method)
			finalUnsoundness := Unsoundness{
				UnprovenMustNotFlows: nil,
				CheckFeatures:        unsoundCheckFeats,
			}
			soundnessResultBase.Soundness = finalUnsoundness.soundness()
			soundnessResultBase.Unsoundness = finalUnsoundness
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
		ctx, s, g, wantFlows, unprovenMustNotFlows, &unsoundness, Types)
	if err != nil {
		soundnessResultBase.Soundness = Error
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
		soundnessResultBase.Soundness = unsoundness.soundness()
		soundnessResultBase.Unsoundness = unsoundness
		soundnessResultBase.Time = time.Since(start)
		soundnessResultBase.Method = method // The algorithm didn't have to recurse here.
		return soundnessResultBase, nil
	}

	// Since we inferred callee summaries, we have intra-procedural results for f.
	// This means that we only need to prove the must-not-flows in the callees.
	calleeResults, soundnessResult, done, err2 := checkCalleeSummaries(
		ctx, s, f, calleeSummaries, specs, soundnessResultBase, unsoundness, start, callStack)
	if done {
		return soundnessResult, err2
	}

	// If all inferred callee summaries are sound, then the summary for f is sound.
	calleesSound := true
	for _, crs := range calleeResults {
		// Only one inferred callee summary needs to be sound.
		calleeSound := false
		for _, cr := range crs {
			if cr.Soundness == Sound {
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
	soundnessResultBase.MethodCounts[Recursive] = len(unprovenMustNotFlows)
	if calleesSound {
		soundnessResultBase.Soundness = unsoundness.soundness()
	} else {
		soundnessResultBase.Soundness = Unsound
	}
	soundnessResultBase.Unsoundness = unsoundness
	soundnessResultBase.Method = Recursive
	soundnessResultBase.Time = time.Since(start)
	soundnessResultBase.CalleeResults = calleeResults
	return soundnessResultBase, nil
}

func checkCalleeSummaries(
	ctx context.Context, s *State, f *ssa.Function,
	calleeSummaries map[*ssa.Function][]summaries.DetailedSummary,
	specs []dataflow.ScanningSpec,
	soundnessResultBase SoundnessResult,
	unsoundness Unsoundness, start time.Time,
	callStack []*ssa.Function,
) ([][]SoundnessResult, SoundnessResult, bool, error) {
	var calleeResults [][]SoundnessResult
	for callee, calleeSumms := range calleeSummaries {
		if len(calleeSumms) == 0 {
			// If there are no callee summaries inferred, this is a bug.
			return nil, SoundnessResult{Soundness: Error}, true,
				fmt.Errorf("no summaries inferred for callee: %s", callee)
		}

		// Assume that multiple recursive calls to a callee makes checking the soundness of the
		// callee impossible. We do this check to avoid looping forever when checking the soundness
		// of recursive functions.
		recursiveCalls := 0
		for _, cf := range callStack {
			if cf.String() == callee.String() {
				recursiveCalls++
			}
		}
		const maxRecursion = 2
		if recursiveCalls > maxRecursion {
			soundnessResultBase.Soundness = Unsound
			soundnessResultBase.Unsoundness = unsoundness
			soundnessResultBase.Time = time.Since(start)
			soundnessResultBase.Method = Recursive
			s.Logger.Warnf(
				"%s is recursive by calling callee %s %d+ times (ctx: %v): assuming unsound\n",
				f, callee, maxRecursion, callStack)
			return nil, soundnessResultBase, true, nil
		}

		var thisCalleeResults []SoundnessResult
		for _, calleeSumm := range calleeSumms {
			// Recursively check the soundness of the callee's inferred summary
			s.Logger.Infof(
				"checking inferred summary for callee %s in %s: %v\n", callee, f, calleeSumm)
			callStack = append(callStack, callee)
			s.Logger.Debugf("call stack: %v\n", callStack)
			calleeRes, err := checkSummary(
				ctx, s, callee, calleeSumm, specs, false, callStack)
			if err != nil {
				s.Logger.Errorf("failed to check callee summary: %v", err)
				if errors.Is(err, errInfer) {
					// If callee summary inference failed, then the result is unsound because
					// the inferred summaries are incomplete/incorrect.
					// Return the must-not-flows for the caller plus any successfully analyzed
					// callees.
					soundnessResultBase.Soundness = Unsound
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
			if calleeRes.Soundness == Sound {
				if len(calleeRes.Unsoundness.UnprovenMustNotFlows) > 0 {
					panic(fmt.Errorf(
						"want no unproven must-not-flows in callee %s summary, got: %v",
						callee, calleeRes.Unsoundness.UnprovenMustNotFlows))
				}
				break
			}
		}

		for _, crs := range calleeResults {
			for _, cr := range crs {
				if cr.Soundness != Sound {
					s.Logger.Infof("unsound deduced callee summary: %v\n", cr.Want)
					soundnessResultBase.Soundness = Unsound
					soundnessResultBase.Unsoundness = unsoundness
					soundnessResultBase.Time = time.Since(start)
					soundnessResultBase.Method = Recursive
					soundnessResultBase.CalleeResults = calleeResults
					return nil, soundnessResultBase, true, nil
				}
			}
		}

		calleeResults = append(calleeResults, thisCalleeResults)
	}
	return calleeResults, SoundnessResult{}, false, nil
}

func checkMethodRead(ctx context.Context, s *State, f *ssa.Function,
	unsoundCheckFeats UnsoundCheckFeatures,
	soundnessResultBase SoundnessResult,
	unprovenMustNotFlows []flow,
	start time.Time) ([]flow, SoundnessResult, bool, error) {
	// The read analysis is unsound if there is reflection, as it depends on the
	// pointer analysis.
	if len(unsoundCheckFeats.ReflectUsages) > 0 {
		s.Logger.Warnf(
			"read analysis is unsound: detected reflection use in function %s\n", f)
		if !s.Config.CheckIgnoresUnsound {
			soundnessResultBase.Soundness = Unsound
			soundnessResultBase.Unsoundness = Unsoundness{
				UnprovenMustNotFlows: funcutil.Map(unprovenMustNotFlows, newFlow),
				CheckFeatures:        unsoundCheckFeats,
			}
			soundnessResultBase.Method = Immutability
			soundnessResultBase.Time = time.Since(start)
			return nil, soundnessResultBase, true, nil
		}
	}
	unprovenMustNotFlows = filterFlowsRead(ctx, s, unprovenMustNotFlows)
	return unprovenMustNotFlows, SoundnessResult{}, false, nil
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
			soundnessResultBase.Soundness = Unsound
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
			soundnessResultBase.Soundness = Unsound
			soundnessResultBase.Unsoundness = Unsoundness{
				UnprovenMustNotFlows: funcutil.Map(unprovenMustNotFlows, newFlow),
				CheckFeatures:        unsoundCheckFeats,
			}
			soundnessResultBase.Time = time.Since(start)
			soundnessResultBase.Method = Types
			return nil, soundnessResultBase, true, nil
		}
	}
	var err error
	unprovenMustNotFlows, err = filterFlowsTypes(unprovenMustNotFlows)
	return unprovenMustNotFlows, SoundnessResult{}, false, err
}

func checkMethodGeneral(s *State, f *ssa.Function,
	unsoundCheckFeats UnsoundCheckFeatures,
	soundnessResultBase SoundnessResult,
	g *dataflow.SummaryGraph,
	wantFlows []flow,
	prec *precisions,
) ([]flow, SoundnessResult, bool, error) {

	// The most-general summary is unsound if there are any globals (as we do not have
	// special global nodes in summaries yet).
	if len(unsoundCheckFeats.GlobalUsages) > 0 {
		s.Logger.Warnf(
			"most-general summary is unsound: detected global use in function %s (%s)\n",
			f, s.Program.Fset.Position(f.Pos()))
		if !s.Config.CheckIgnoresUnsound {
			unsoundness := Unsoundness{CheckFeatures: unsoundCheckFeats}
			soundnessResultBase.Soundness = unsoundness.soundness()
			soundnessResultBase.Unsoundness = unsoundness
			soundnessResultBase.Method = General
			return nil, soundnessResultBase, true, nil
		}
	}
	// The most-general analysis is unsound if there is unsafe, as unsafe memory operations can
	// make new input/output nodes that are not in the summary.
	if len(unsoundCheckFeats.UnsafeUsages) > 0 {
		s.Logger.Warnf(
			"most-general analysis is unsound: detected unsafe use in function %s\n", f)
		if !s.Config.CheckIgnoresUnsound {
			unsoundness := Unsoundness{CheckFeatures: unsoundCheckFeats}
			soundnessResultBase.Soundness = unsoundness.soundness()
			soundnessResultBase.Unsoundness = unsoundness
			soundnessResultBase.Method = General
			return nil, soundnessResultBase, true, nil
		}
	}

	unprovenMustNotFlows, err := checkSummaryMostGeneral(s.Logger, g, prec, wantFlows)
	if err != nil {
		return unprovenMustNotFlows, soundnessResultBase, false,
			fmt.Errorf("failed to check summary via most-general: %v", err)
	}

	// We only need to add the precision of the unproven must-not-flows once, because the set of
	// unproven must-not-flows only shrinks with each analysis.
	updateNodePrecisions(prec, unprovenMustNotFlows)

	return unprovenMustNotFlows, soundnessResultBase, false, nil
}

func checkMethodNaive(ctx context.Context, s *State,
	unsoundCheckFeats UnsoundCheckFeatures,
	soundnessResultBase SoundnessResult,
	g *dataflow.SummaryGraph,
	want summaries.DetailedSummary,
	start time.Time,
	specs []dataflow.ScanningSpec) ([]flow, SoundnessResult, bool, error) {
	// Summaries are built lazily on demand (see onDemandIntraProcedural) rather than eagerly here,
	// since eagerly building every reachable function per checked summary doesn't scale. Global
	// write->read jumps (the one case that used to need the eager pass) are now handled directly
	// in Visit's AccessGlobalNode case.
	s.RunIntraProceduralPass(ctx, -1, dataflow.IntraAnalysisParams{
		ShouldBuildSummary: func(*dataflow.State, *ssa.Function) bool { return false },
	})
	s.FlowGraph.BuildGraph(true)
	checkResult, err := ComputeClosedSummary(ctx, s.State, g.Parent, specs)
	if err != nil {
		soundnessResultBase.Soundness = Error
		soundnessResultBase.Unsoundness = Unsoundness{
			UnprovenMustNotFlows: []Flow{},
			BadForm:              err,
			CheckFeatures:        unsoundCheckFeats,
			DataflowFeatures: UnsoundDataflowFeatures{
				TimedOut: errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
			},
		}
		soundnessResultBase.Method = Naive
		soundnessResultBase.Time = time.Since(start)
		return nil, soundnessResultBase, true, nil
	}
	computed, err := checkResult.ToDetailedSummary()
	if err != nil {
		soundnessResultBase.Soundness = Error
		soundnessResultBase.Unsoundness = Unsoundness{
			UnprovenMustNotFlows: []Flow{},
			BadForm:              err,
			CheckFeatures:        unsoundCheckFeats,
		}
		soundnessResultBase.Method = Naive
		soundnessResultBase.Time = time.Since(start)
		return nil, soundnessResultBase, true, nil
	}
	s.Logger.Infof("computed summary:\n%s\n", computed.String())
	soundnessResultBase.Got = computed
	if !want.IsMoreGeneralThan(computed) {
		soundnessResultBase.Soundness = Unsound
		soundnessResultBase.Unsoundness = checkResult.Unsoundness
		soundnessResultBase.Method = Naive
		soundnessResultBase.Time = time.Since(start)
		return nil, soundnessResultBase, true, nil
	}
	if !checkResult.Unsoundness.isSound() {
		soundnessResultBase.Soundness = checkResult.Unsoundness.soundness()
		soundnessResultBase.Unsoundness = checkResult.Unsoundness
		soundnessResultBase.Method = Naive
		soundnessResultBase.Time = time.Since(start)
		return nil, soundnessResultBase, true, nil
	}
	soundnessResultBase.Method = Naive
	soundnessResultBase.MethodCounts[Naive] = 1
	soundnessResultBase.Time = time.Since(start)

	return []flow{}, soundnessResultBase, true, nil
}

// flow is a data flow between two summary graph nodes.
type flow struct {
	from graphNode
	to   graphNode
}

func (f flow) String() string {
	return fmt.Sprintf("%s%s->%s%s", graphNodeDesc(f.from.node), f.from.path.String(), graphNodeDesc(f.to.node), f.to.path.String())
}

// graphNode is a dataflow.GraphNode augmented with an (empty or non-empty) access path.
// If path is empty, that means that the graphNode refers to *all* access paths.
type graphNode struct {
	node dataflow.GraphNode
	path path
}

func (n graphNode) String() string {
	pathStr := n.path.String()
	return graphNodeDesc(n.node) + pathStr
}

// maxPathLen is the maximum path length.
// We set it to 3 which matches the dataflow package's restriction.
const maxPathLen = 3

type path [maxPathLen]string

const emptyPath = ""

// newPath parses p and returns a path.
// The length of the path is bounded by min(maxLen, maxPathLen).
func newPath(p string, maxLen int) path {
	if len(p) == 0 || maxLen == 0 {
		return path{}
	}
	maxLen = min(maxLen, maxPathLen)

	trimmed := strings.TrimPrefix(p, ".")
	if len(trimmed) == 0 {
		return path{}
	}
	pth := strings.Split(trimmed, ".")
	// The path element suffix "[*]" represents all elements of the array/slice/map.
	// There is no actual difference between a path element "f" and "f[*]" in practice so we
	// simplify the latter to the former.
	pth = funcutil.Map(pth, func(el string) string { return strings.ReplaceAll(el, "[*]", "") })
	var res path
	for i, el := range pth {
		res[i] = el
		if i == maxLen-1 {
			break
		}
	}

	return res
}

func (p path) len() int {
	if len(p[0]) == 0 {
		return 0
	}

	for i, el := range p {
		if len(el) == 0 {
			return i
		}
	}

	return maxPathLen
}

// isCoveredBy is true iff x is covered by p; i.e, p's path is a prefix of x's path.
//
// Stated another way, x's path *has* a prefix of p's path.
func (p path) isCoveredBy(x path) bool {
	return strings.HasPrefix(x.String(), p.String())
}

func (p path) String() string {
	pLen := p.len()
	if pLen == 0 {
		return emptyPath
	}
	parts := make([]string, pLen)
	for i := range pLen {
		parts[i] = p[i]
	}
	return "." + strings.Join(parts, ".")
}

func newGraphNode(n dataflow.GraphNode, objPath string) graphNode {
	if len(objPath) == 0 {
		return graphNode{n, path{}}
	}
	p := newPath(objPath, maxPathLen)
	return graphNode{n, p}
}

// precisions is the precision for the summary inputs and outputs.
//
// Since our static analyses (for now) check for each flow, whether the input to the flow or the
// output from the flow are valid, it makes sense to minimize the precision for each flow
// input/output. We want to minimize the precision because of access path subsumption: a -> b
// implies a.f -> b.f. Minimizing precision also makes the static analyses more efficient.
// For example, given the summary { a -> b, a.f -> b, a -> b.f }, the access path length for input
// `a` is 0 and output `b` is also 0.
// However, given the summary { a.f -> b.f, b -> a, b.f -> a.f }, the access path length for input
// `a` is 1, output `a` is 0, input `b` is 0, and output `b` is 1.
type precisions struct {
	inputs         precision
	outputs        precision
	longestPathLen int
}

func newPrecisions(flows []flow) *precisions {
	in := newInputPrecision(flows)
	out := newOutputPrecision(flows)
	return &precisions{
		inputs:         in,
		outputs:        out,
		longestPathLen: max(in.longestPathLen, out.longestPathLen),
	}
}

type precision struct {
	nodePathLen    map[dataflow.GraphNode]int
	longestPathLen int
}

func newInputPrecision(flows []flow) precision {
	nodePathLen := make(map[dataflow.GraphNode]int)
	longest := 0
	for _, fl := range flows {
		pln, ok := nodePathLen[fl.from.node]
		if !ok {
			pln = fl.from.path.len()
			nodePathLen[fl.from.node] = pln
		}
		nodePathLen[fl.from.node] = min(nodePathLen[fl.from.node], pln)
		pln = nodePathLen[fl.from.node]
		longest = max(longest, pln)
	}

	return precision{
		nodePathLen:    nodePathLen,
		longestPathLen: longest,
	}
}

func newOutputPrecision(flows []flow) precision {
	nodePathLen := make(map[dataflow.GraphNode]int)
	longest := 0
	for _, fl := range flows {
		pln, ok := nodePathLen[fl.to.node]
		if !ok {
			pln = fl.to.path.len()
			nodePathLen[fl.to.node] = pln
		}
		nodePathLen[fl.to.node] = min(nodePathLen[fl.to.node], pln)

		pln = nodePathLen[fl.to.node]
		longest = max(longest, pln)
	}

	return precision{
		nodePathLen:    nodePathLen,
		longestPathLen: longest,
	}
}

// updateNodePrecisions updates prec for flows in the same way as newPrecisions.
// It only updates nodePathLen for inputs and outputs, not valPathLen.
func updateNodePrecisions(prec *precisions, flows []flow) {
	for _, fl := range flows {
		inLen, ok := prec.inputs.nodePathLen[fl.from.node]
		if !ok {
			inLen = fl.from.path.len()
		}
		prec.inputs.nodePathLen[fl.from.node] = min(prec.inputs.nodePathLen[fl.from.node], inLen)

		outLen, ok := prec.outputs.nodePathLen[fl.to.node]
		if !ok {
			outLen = fl.to.path.len()
		}
		prec.outputs.nodePathLen[fl.to.node] = min(prec.outputs.nodePathLen[fl.to.node], outLen)

		// longestPathLen should be the same since the must-not-flows are derived from the wantFlows.
	}
}

func graphNodeDesc(g dataflow.GraphNode) string {
	switch x := g.(type) {
	case *dataflow.ParamNode:
		return fmt.Sprintf("param:%s", x.SsaNode().Name())
	case *dataflow.CallNode:
		return fmt.Sprintf("call:%s", x.CallSite().String())
	case *dataflow.BuiltinCallNode:
		return fmt.Sprintf("builtin-call:%s", x.CallSite().String())
	case *dataflow.CallNodeArg:
		return fmt.Sprintf("arg#%v:%s", x.Index(), x.ParentNode().CallSite().String())
	case *dataflow.ReturnValNode:
		return fmt.Sprintf("ret#%d", x.Index())
	case *dataflow.BoundVarNode:
		return fmt.Sprintf("bound-var:%s", x.Value().Name())
	case *dataflow.FreeVarNode:
		return fmt.Sprintf("free-var:%s", x.SsaNode().Name())
	case *dataflow.AccessGlobalNode:
		return fmt.Sprintf("global:%v", x.Global.Value())
	case *dataflow.ClosureNode:
		return fmt.Sprintf("closure:%v", x.Instr())
	default:
		// NOTE Should be unreachable.
		panic(fmt.Errorf("unsupported node type: %v %T", g, g))
	}
}
