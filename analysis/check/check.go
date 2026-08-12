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
	"go/types"
	"slices"
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
	// readCache caches the result of checkReads for a given (value, path), since the result
	// depends only on those two values, not on the flow being checked. Without this, the same
	// (value, path) can be re-walked via checkReads' full call-graph BFS once per candidate flow
	// that shares it as a "from", which is one per output field state pairs it with.
	readCache map[value]readCacheEntry
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
		readCache:     make(map[value]readCacheEntry),
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
	// NOTE Hardcode config so we don't make unintentional mistakes.
	s.Config.DataflowProblems.CheckIgnoresUnsound = true

	// SPECIAL CASE: INTERFACES
	if ifaceSummary, isIfaceSummary := want.(summaries.IfaceMethodFlowSummary); isIfaceSummary {
		// Checking a summary that is for a method of an interface
		// This means we need to gather all the possible implementations, and check every single one.
		implementations := s.ImplementationsByType
		key := lang.MethodKey(ifaceSummary.Package()+"."+ifaceSummary.Interface, ifaceSummary.Method)
		if implems, isPresent := implementations[key]; isPresent {
			if err := ValidateSummary(want.Summary()); err != nil {
				return []SoundnessResult{newInvalidSummaryResult(want, err)}, true, err
			}
			var res []SoundnessResult
			var errs []error
			for implem := range implems {
				if err := checkReachable(s, implem); err != nil {
					s.Logger.Errorf("skipping implementation %s: %v", implem, err)
					errs = append(errs, err)
					continue
				}
				s.Logger.Infof(
					"Checking that interface summary for %s is sound for implementation %s",
					want.Name(), implem.RelString(nil))
				callStack := []*ssa.Function{implem}
				partRes, err := checkSummary(
					ctx, s, implem, want.Summary(), specs, testNaive, callStack, true, pathBound{})
				partRes.SummaryName = want.Name()
				res = append(res, partRes)
				if err != nil {
					s.Logger.Errorf("failed to check implementation %s: %v", implem, err)
					errs = append(errs, err)
				}
			}
			return res, true, errors.Join(errs...)
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
	if err := checkReachable(s, f); err != nil {
		return []SoundnessResult{}, false, err
	}
	if err := ValidateSummary(want.Summary()); err != nil {
		return []SoundnessResult{newInvalidSummaryResult(want, err)}, true, err
	}

	s.Logger.Infof("checking the soundness of summary %s ...\n", want.Summary())
	callStack := []*ssa.Function{f}
	res, err := checkSummary(ctx, s, f, want.Summary(), specs, testNaive, callStack, false, pathBound{})
	res.SummaryName = want.Name()
	return []SoundnessResult{res}, true, err
}

// newInvalidSummaryResult builds the SoundnessResult for a summary that is syntactically invalid.
func newInvalidSummaryResult(want summaries.FrontendDataflowSummary, err error) SoundnessResult {
	return SoundnessResult{
		Name:        want.Name(),
		SummaryName: want.Name(),
		Want:        want.Summary(),
		Soundness:   Error,
		Unsoundness: Unsoundness{
			UnprovenMustNotFlows: []Flow{},
			BadForm:              err,
		},
	}
}

var errInfer = errors.New("failed to infer callee summaries")

// errUnreachable is returned for a function that the pointer analysis did not find reachable.
var errUnreachable = errors.New("function is not reachable")

// checkReachable rejects a function the pointer analysis never reached, before any soundness checking
// runs.
//
// Every method the checker uses to prove a must-not-flow absent reasons over the function's body and
// the bodies it can call, using structures the pointer analysis populated: checkReads walks out from
// f's call graph node, checkWritesPtr and the type analysis consult points-to sets, and the flow graph
// is built from f's summary graph. For a function outside the call graph all of those are empty, so
// every must-not-flow comes back vacuously proven and the summary is reported sound on no evidence at
// all. That is not a conservative default worth having deeper in the pipeline: there is no useful
// answer to give, so refuse the request here instead.
func checkReachable(s *State, f *ssa.Function) error {
	if s.IsReachableFunction(f) {
		return nil
	}
	return fmt.Errorf("%w: %s is not reachable from the analysis entry points, so there is"+
		" nothing to check its summary against", errUnreachable, f)
}

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
// demanded is the access path bound the caller relied on when it deduced want, empty at the outermost
// call. It travels separately from want because want's own syntax only records the bound the *callee*
// needs: a summary that mentions no field is read field-insensitively, and read that way it admits a
// flow between any two fields of a position. If the caller told those fields apart and discharged a
// must-not-flow by relying on that flow being absent, checking want at its own bound proves something
// weaker than the caller assumed. Widening to demanded is what closes that gap.
//
//gocyclo:ignore
func checkSummary(
	ctx context.Context, s *State, f *ssa.Function, want summaries.DetailedSummary,
	specs []dataflow.ScanningSpec, testNaive bool, callStack []*ssa.Function, isInterfaceImpl bool,
	demanded pathBound,
) (SoundnessResult, error) {
	// The checkable summary format has no syntax for a top-level closure's free variables, so
	// reject f if it's a closure -- but only at the outermost call (len(callStack) == 1):
	// recursively-checked callees use an inferred summary, which does support free variables.
	if len(callStack) == 1 && len(f.FreeVars) > 0 {
		return SoundnessResult{Soundness: Error},
			fmt.Errorf("cannot check soundness of %s: it is a closure with free variables, which "+
				"the checkable summary format cannot express for a top-level target", f)
	}
	// The checkable summary format has no syntax for a function-typed input or output, so reject
	// f if it is higher-order.
	if len(callStack) == 1 {
		if path, ok := higherOrderInputOrOutput(f); ok {
			return SoundnessResult{Soundness: Error},
				fmt.Errorf("cannot check soundness of %s: it is higher-order (%s resolves to a "+
					"function type), which the checkable summary format cannot express", f, path)
		}
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
			ctx, s, unsoundCheckFeats, soundnessResultBase, g, want, start, specs, isInterfaceImpl)
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

	// The bound this summary is read against: under each position, as deep as the longest access
	// path the summary names there. Widened by the bound the caller demanded of this function, so a
	// distinction the caller relied on is still deniable here.
	bounds := boundsOfFlows(wantFlows)
	bounds.widenTo(g, demanded)
	s.Logger.Debugf("access path bounds: %+v\n", bounds.toPathBound())

	for _, m := range []Method{General, Types, Immutability, Read} {
		method = m
		var soundnessResult SoundnessResult
		var done bool
		var err error
		beforeCount := len(unprovenMustNotFlows)
		switch method {
		case General:
			unprovenMustNotFlows, soundnessResult, done, err = checkMethodGeneral(
				s, f, unsoundCheckFeats, soundnessResultBase, g, wantFlows, &bounds)
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
	calleeSummaries, calleeGraph, err := inferCalleeSummaries(
		ctx, s, g, wantFlows, unprovenMustNotFlows, &unsoundness, Types)
	if err != nil {
		soundnessResultBase.Soundness = Error
		soundnessResultBase.Unsoundness = unsoundness
		soundnessResultBase.Time = time.Since(start)
		soundnessResultBase.Method = Recursive
		// Wraps both the sentinel and the cause: callers test errors.Is against errInfer to decide how
		// to report, and against context.DeadlineExceeded to set TimedOut. Wrapping only the sentinel
		// loses the latter silently.
		return soundnessResultBase, fmt.Errorf("%w for %s: %w", errInfer, f, err)
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
		ctx, s, f, calleeSummaries, calleeGraph.demands, specs, soundnessResultBase, unsoundness,
		start, callStack)
	if done {
		return soundnessResult, err2
	}

	// If all inferred callee summaries are sound, then the summary for f is sound.
	// unsoundCalleeFlows maps each callee for which none of the inferred summary variants could be
	// proven sound to the union of those variants' own reported UnprovenMustNotFlows (since we
	// don't know which variant, if any, matches the callee's real behavior, we conservatively
	// assume any of their unproven flows could be real).
	calleesSound := true
	// anyTrustedCalleeSoundy is true if some callee was only trusted via a Soundy variant, in
	// which case f's own Soundness is widened from Sound to Soundy below.
	anyTrustedCalleeSoundy := false
	unsoundCalleeFlows := map[*ssa.Function][]Flow{}
	for _, crs := range calleeResults {
		if len(crs) == 0 {
			continue
		}
		// Only one inferred callee summary needs to be sound.
		calleeSound := false
		for _, cr := range crs {
			if cr.Soundness.provenSound() {
				calleeSound = true
				if cr.Soundness == Soundy {
					anyTrustedCalleeSoundy = true
				}
				break
			}
		}
		if !calleeSound {
			calleesSound = false
			callee := crs[0].Fn
			for _, cr := range crs {
				unsoundCalleeFlows[callee] = append(
					unsoundCalleeFlows[callee], cr.Unsoundness.UnprovenMustNotFlows...)
			}
		}
	}
	if calleesSound {
		unsoundness.UnprovenMustNotFlows = nil
	} else {
		stillUnproven, pruneErr := unprovenFlowsAfterCalleeCheck(
			ctx, s, g, wantFlows, unprovenMustNotFlows, calleeGraph, unsoundCalleeFlows)
		if pruneErr != nil {
			return soundnessResultBase, fmt.Errorf(
				"failed to determine unproven must-not-flows after callee check for %s: %v", f, pruneErr)
		}
		unsoundness.UnprovenMustNotFlows = funcutil.Map(stillUnproven, newFlow)
	}

	soundnessResultBase.MethodCounts[Recursive] = len(unprovenMustNotFlows)
	// unsoundness.soundness() already returns Unsound whenever UnprovenMustNotFlows is non-empty,
	// which covers the calleesSound == false case where pruning left some flows unproven. This
	// call also covers calleesSound == true (list is nil) and calleesSound == false with every
	// flow pruned (list is empty): both rely on CheckFeatures/DataflowFeatures to decide between
	// Sound and Soundy instead of hardcoding Sound.
	finalSoundness := unsoundness.soundness()
	// Widen Sound to Soundy if a trusted callee was itself only Soundy; never touch Unsound/Error.
	if anyTrustedCalleeSoundy && finalSoundness == Sound {
		finalSoundness = Soundy
	}
	soundnessResultBase.Soundness = finalSoundness
	soundnessResultBase.Unsoundness = unsoundness
	soundnessResultBase.Method = Recursive
	soundnessResultBase.Time = time.Since(start)
	soundnessResultBase.CalleeResults = calleeResults
	return soundnessResultBase, nil
}

// isHigherOrderType reports whether t or an access path into it resolves to a function type. It
// descends through pointers, struct fields, array/slice elements, and map keys/values, since a
// summary input/output can alias into any of them; it stops at interfaces, whose concrete type is
// not statically known. Named types can be recursive (e.g. a linked list), so visited types are
// tracked to terminate on a cycle instead of resolving one as higher-order.
func isHigherOrderType(t types.Type) bool {
	return isHigherOrderTypeVisiting(t, make(map[types.Type]bool))
}

func isHigherOrderTypeVisiting(t types.Type, seen map[types.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t := t.(type) {
	case *types.Signature:
		return true
	case *types.Pointer:
		return isHigherOrderTypeVisiting(t.Elem(), seen)
	case *types.Named:
		return isHigherOrderTypeVisiting(t.Underlying(), seen)
	case *types.Alias:
		return isHigherOrderTypeVisiting(t.Underlying(), seen)
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			if isHigherOrderTypeVisiting(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Array:
		return isHigherOrderTypeVisiting(t.Elem(), seen)
	case *types.Slice:
		return isHigherOrderTypeVisiting(t.Elem(), seen)
	case *types.Map:
		return isHigherOrderTypeVisiting(t.Key(), seen) || isHigherOrderTypeVisiting(t.Elem(), seen)
	case *types.Chan:
		return isHigherOrderTypeVisiting(t.Elem(), seen)
	}
	return false
}

// higherOrderInputOrOutput reports the name of the first parameter, receiver, or return value of f
// whose type is higher-order (see isHigherOrderType), if any.
func higherOrderInputOrOutput(f *ssa.Function) (string, bool) {
	for _, p := range f.Params {
		if isHigherOrderType(p.Type()) {
			return p.Name(), true
		}
	}
	results := f.Signature.Results()
	for i, n := 0, results.Len(); i < n; i++ {
		if isHigherOrderType(results.At(i).Type()) {
			return fmt.Sprintf("return value %d", i), true
		}
	}
	return "", false
}

func checkCalleeSummaries(
	ctx context.Context, s *State, f *ssa.Function,
	calleeSummaries map[*ssa.Function][]summaries.DetailedSummary,
	calleeDemands calleeBounds,
	specs []dataflow.ScanningSpec,
	soundnessResultBase SoundnessResult,
	unsoundness Unsoundness, start time.Time,
	callStack []*ssa.Function,
) ([][]SoundnessResult, SoundnessResult, bool, error) {
	var calleeResults [][]SoundnessResult
	// Iterate callees in a deterministic order: calleeSummaries is keyed by *ssa.Function, so
	// ranging over it directly varies per run. That order is observable in the result -- it fixes
	// the order of calleeResults, and each callee's check contributes to unsoundCalleeFlows, which
	// later callees' checks and the final verdict depend on.
	callees := make([]*ssa.Function, 0, len(calleeSummaries))
	for callee := range calleeSummaries {
		callees = append(callees, callee)
	}
	slices.SortFunc(callees, func(a, b *ssa.Function) int {
		return strings.Compare(a.String(), b.String())
	})
	for _, callee := range callees {
		calleeSumms := calleeSummaries[callee]
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
				ctx, s, callee, calleeSumm, specs, false, callStack, false, calleeDemands[callee])
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
			if calleeRes.Soundness.provenSound() {
				if len(calleeRes.Unsoundness.UnprovenMustNotFlows) > 0 {
					panic(fmt.Errorf(
						"want no unproven must-not-flows in callee %s summary, got: %v",
						callee, calleeRes.Unsoundness.UnprovenMustNotFlows))
				}
				break
			}
		}

		// NOTE We deliberately don't exit early here even if none of this callee's summary
		// variants are sound: the caller (checkSummary) needs the full set of callee results,
		// including for callees processed later in this loop, to determine precisely which
		// must-not-flows remain unproven (a must-not-flow is only unproven if it depends on this
		// specific unsound callee; see unprovenFlowsAfterCalleeCheck).
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
	bounds *nodeBounds,
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

	unprovenMustNotFlows, err := checkSummaryMostGeneral(s.Logger, g, *bounds, wantFlows)
	if err != nil {
		return unprovenMustNotFlows, soundnessResultBase, false,
			fmt.Errorf("failed to check summary via most-general: %v", err)
	}

	// The must-not-flows can name a position more deeply than the summary itself does, so widen
	// once. The set of unproven must-not-flows only shrinks with each analysis, so once is enough.
	for _, fl := range unprovenMustNotFlows {
		bounds.record(fl.from.node, fl.from.path)
		bounds.record(fl.to.node, fl.to.path)
	}

	return unprovenMustNotFlows, soundnessResultBase, false, nil
}

func checkMethodNaive(ctx context.Context, s *State,
	unsoundCheckFeats UnsoundCheckFeatures,
	soundnessResultBase SoundnessResult,
	g *dataflow.SummaryGraph,
	want summaries.DetailedSummary,
	start time.Time,
	specs []dataflow.ScanningSpec,
	isInterfaceImpl bool) ([]flow, SoundnessResult, bool, error) {
	// Summaries are built lazily on demand (see onDemandIntraProcedural) rather than eagerly here,
	// since eagerly building every reachable function per checked summary doesn't scale. Global
	// write->read jumps (the one case that used to need the eager pass) are now handled directly
	// in Visit's AccessGlobalNode case.
	s.RunIntraProceduralPass(ctx, -1, dataflow.IntraAnalysisParams{
		ShouldBuildSummary: func(*dataflow.State, *ssa.Function) bool { return false },
	})
	// Build the inter-procedural data-flow graph, using contracts and predefined stdlib
	// summaries when available.
	s.FlowGraph.BuildGraph(true)
	checkResult, err := ComputeClosedSummary(ctx, s.State, g.Parent, specs, isInterfaceImpl)
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
	from summaryNode
	to   summaryNode
}

func (f flow) String() string {
	return fmt.Sprintf("%s%s->%s%s", graphNodeDesc(f.from.node), f.from.path.String(), graphNodeDesc(f.to.node), f.to.path.String())
}

// summaryNode is a position in a function's dataflow summary: a dataflow.GraphNode plus an access
// path into it. An empty path refers to *all* access paths under that node.
//
// It is the base of a three-level flow-endpoint vocabulary, each level adding exactly the context the
// next stage of the analysis needs:
//
//   - summaryNode: a position in one function's summary, with no calling context. This is what a
//     must-not-flow names and what gets reported to the user (see frontendNode, which maps it into
//     the exported summaries.SummaryNode vocabulary).
//   - calledSummaryNode: summaryNode plus the call site whose frame it is in. Needed because a
//     callee's summary graph is shared across all of its call sites, so without the frame, nodes for
//     two calls to the same function merge.
//   - vertex: calledSummaryNode plus the traversal state the construction fixpoint carries.
type summaryNode struct {
	node dataflow.GraphNode
	path path
}

func (n summaryNode) String() string {
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

// subsumes is true iff p subsumes x; i.e, p's path is a segment-wise prefix of x's path, so p denotes
// memory containing x.
//
// This compares path segments individually (not the joined dotted string) so that, e.g.,
// "Body" is not considered a prefix of "BodyStart": they are sibling field names that happen to
// share a string prefix, not one path containing the other.
func (p path) subsumes(x path) bool {
	pLen := p.len()
	if pLen > x.len() {
		return false
	}
	for i := range pLen {
		if p[i] != x[i] {
			return false
		}
	}
	return true
}

// overlaps reports whether two access paths denote overlapping memory, i.e. whether either subsumes
// the other.
func overlaps(a, b path) bool {
	return a.subsumes(b) || b.subsumes(a)
}

// truncate returns p keeping only its first k segments.
func (p path) truncate(k int) path {
	for i := k; i < maxPathLen; i++ {
		p[i] = ""
	}
	return p
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

func newSummaryNode(n dataflow.GraphNode, objPath string) summaryNode {
	if len(objPath) == 0 {
		return summaryNode{n, path{}}
	}
	p := newPath(objPath, maxPathLen)
	return summaryNode{n, p}
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
	case *dataflow.BoundLabelNode:
		return fmt.Sprintf("bound-label:%v", x.Instr())
	case *dataflow.SyntheticNode:
		return fmt.Sprintf("synthetic:%v", x.Instr())
	case *dataflow.IfNode:
		return fmt.Sprintf("if:%v", x.SsaNode())
	default:
		// Every node kind the flow graph can contain needs a description: graphNodeDesc names the
		// maxsat reachability variables and orders edges, so it is reached for every vertex, not
		// just the ones that can be summary endpoints.
		return fmt.Sprintf("node:%T:%v", g, g)
	}
}
