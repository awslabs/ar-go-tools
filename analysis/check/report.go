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
	"bytes"
	"encoding/json"
	"fmt"
	"go/token"
	"strings"
	"time"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// SoundnessResult is the result of checking the soundness of a single data flow summary.
type SoundnessResult struct {
	Fn *ssa.Function
	// Name is the qualified name of the summarized function.
	Name string
	// SummaryName is the name of the top-level summary entry (from the checked specs file)
	// that this result was produced for. For an interface method, this is the interface
	// method's own name (e.g. "(fmt.Stringer).String"), shared by every concrete
	// implementation's result; for a plain function or method, it equals Name. Only set on
	// the top-level result returned by CheckSummary, not on CalleeResults (which have no
	// corresponding user-facing spec entry).
	SummaryName string
	// Want is the summary being checked.
	Want summaries.DetailedSummary
	// Got is the summary actually computed by the full (naive) data flow analysis. It is only
	// populated when Method is Naive: the other checking methods never compute a complete summary
	// for the function, only a set of unproven must-not-flows.
	Got summaries.DetailedSummary
	// Soundness classifies the outcome of the check: sound, soundy, unsound, or error (the check
	// could not be attempted).
	Soundness Soundness
	// Unsoundness is the potential sources of unsoundness in the soundness check.
	Unsoundness Unsoundness
	// Method is the least powerful method needed to be used for the soundness check.
	Method Method
	// MethodCounts records how many must-not-flows each method proved.
	MethodCounts map[Method]int
	// Time is the time spent to calculate the result.
	Time time.Duration
	// CalleeResults are the soundness results of the callees.
	// It's a slice of slices because there may be multiple inferred callee summaries.
	CalleeResults [][]SoundnessResult
}

// String returns a JSON representation of the soundness result.
func (r SoundnessResult) String() string {
	b, err := r.MarshalJSON()
	if err != nil {
		panic(fmt.Errorf("failed to marshal soundness result for function %s to JSON: %v", r.Name, err))
	}

	return string(b)
}

// PrettyString returns a pretty-printed version of the soundness result.
//
//gocyclo:ignore
func (r SoundnessResult) PrettyString() string {
	s := strings.Builder{}
	switch r.Soundness {
	case Sound:
		s.WriteString(fmt.Sprintf("%s: %s\n",
			formatutil.BgBlue(r.Name), formatutil.BgGreen(" sound ")))
	case Soundy:
		s.WriteString(fmt.Sprintf("%s: %s\n",
			formatutil.BgBlue(r.Name), formatutil.BgOrange(" soundy ")))
	default:
		s.WriteString(fmt.Sprintf("%s: %s\n",
			formatutil.BgBlue(r.Name), formatutil.BgRed(fmt.Sprintf(" %s ", r.Soundness))))
	}
	s.WriteString(fmt.Sprintf("  Method: %s\n", r.Method))
	s.WriteString("  Checked summary:\n")
	for origin, dests := range r.Want.Flows {
		s.WriteString(fmt.Sprintf("  %s flows to %s\n", formatutil.BgDarkGray(origin.String()),
			strings.Join(
				funcutil.Map(dests,
					func(n summaries.SummaryNode) string { return formatutil.BgDarkGray(n.String()) }), ", ")))
	}
	if r.Method == Naive {
		s.WriteString("  Computed summary (naive):\n")
		for origin, dests := range r.Got.Flows {
			s.WriteString(fmt.Sprintf("  %s flows to %s\n", formatutil.BgDarkGray(origin.String()),
				strings.Join(
					funcutil.Map(dests,
						func(n summaries.SummaryNode) string { return formatutil.BgDarkGray(n.String()) }), ", ")))
		}
	}
	if r.Soundness != Sound {
		s.WriteString("  The summary is unsound because:\n")
		if r.Unsoundness.BadForm != nil {
			s.WriteString(fmt.Sprintf("    Summary is malformed: %s\n", r.Unsoundness.BadForm.Error()))
		}
		if len(r.Unsoundness.UnprovenMustNotFlows) > 0 {
			s.WriteString("    Could not prove that the following flows do not exist:\n")
			for _, unprovenFlow := range r.Unsoundness.UnprovenMustNotFlows {
				s.WriteString(fmt.Sprintf("      - %s\n", unprovenFlow))
			}
		}
		if !r.Unsoundness.CheckFeatures.isSound() {
			s.WriteString(
				"    There are some features which make the soundness checking algorithm unsound.\n")
			if len(r.Unsoundness.CheckFeatures.GlobalUsages) > 0 {
				s.WriteString("    Global variables are used, which may cause unsoundness\n")
				for _, pos := range r.Unsoundness.CheckFeatures.GlobalUsages {
					s.WriteString(fmt.Sprintf("     - %s\n", pos))
				}
			}
			if len(r.Unsoundness.CheckFeatures.UnsafeUsages) > 0 {
				s.WriteString("    Unsafe is used, which may cause unsoundness\n")
				for _, pos := range r.Unsoundness.CheckFeatures.UnsafeUsages {
					s.WriteString(fmt.Sprintf("      - %s\n", pos))
				}
			}
			if len(r.Unsoundness.CheckFeatures.ReflectUsages) > 0 {
				s.WriteString("    Reflection is used, which may allow arbitrary memory access\n")
				for _, pos := range r.Unsoundness.CheckFeatures.ReflectUsages {
					s.WriteString(fmt.Sprintf("      - %s\n", pos))
				}
			}
			if len(r.Unsoundness.CheckFeatures.NonLocalBoundLabelUsages) > 0 {
				s.WriteString("    Non-local bound labels is used, which are not supported\n")
				for _, pos := range r.Unsoundness.CheckFeatures.NonLocalBoundLabelUsages {
					s.WriteString(fmt.Sprintf("      - %s\n", pos))
				}
			}
		}
		if !r.Unsoundness.DataflowFeatures.isSound() {
			s.WriteString(
				"    There are some features which make the dataflow analysis unsound.\n")
			if len(r.Unsoundness.DataflowFeatures.RecoverUsages) > 0 {
				s.WriteString("    Recover is used, which may allow arbitrary memory access\n")
				for _, pos := range r.Unsoundness.DataflowFeatures.RecoverUsages {
					s.WriteString(fmt.Sprintf("      - %s\n", pos))
				}
			}
			if r.Unsoundness.DataflowFeatures.HasUnboundedDefers {
				s.WriteString("    Function has unbounded defer stack, which may cause unsoundness\n")
			}
			if len(r.Unsoundness.DataflowFeatures.GoUsages) > 0 {
				s.WriteString("    Go statements are used, which may cause unsoundness\n")
				for _, pos := range r.Unsoundness.DataflowFeatures.GoUsages {
					s.WriteString(fmt.Sprintf("      - %s\n", pos))
				}
			}
		}
		s.WriteString(fmt.Sprintf("  Time spent: %s\n", r.Time))
	}
	return s.String()
}

// MarshalJSON implements the json.Marshaler interface for SoundnessResult.
func (r SoundnessResult) MarshalJSON() ([]byte, error) {
	b := &bytes.Buffer{}
	raw := newRawSoundnessResult(r)
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false) // don't escape characters like "<"
	enc.SetIndent("", "  ")  // indent by 2 spaces (no prefix)
	err := enc.Encode(raw)
	res := b.Bytes()
	return res, err
}

// Unsoundness is the source(s) of unsoundness in the summary checking algorithm.
type Unsoundness struct {
	// BadForm indicates that the summary is not in the expected form, and there was an error building it.
	BadForm error
	// UnprovenMustNotFlows are the must-not-flows unable to be proven.
	UnprovenMustNotFlows []Flow
	// CheckFeatures are the unsound features that make the checking algorithm unsound.
	CheckFeatures UnsoundCheckFeatures
	// DataflowFeatures are the unsound features that make the data flow analysis unsound.
	DataflowFeatures UnsoundDataflowFeatures
}

// Soundness classifies the outcome of a soundness check.
type Soundness string

const (
	// Sound: all must-not-flows were proven, with no unsoundness risk features.
	Sound Soundness = "sound"
	// Soundy: all must-not-flows were proven, but an unsoundness risk feature was found (e.g.
	// reflection, unsafe, a global, a timeout).
	Soundy Soundness = "soundy"
	// Unsound: at least one must-not-flow could not be proven.
	Unsound Soundness = "unsound"
	// Error: the check could not be attempted (e.g. a malformed summary, or a closure target that
	// the checkable summary format cannot express).
	Error Soundness = "error"
)

func (u Unsoundness) soundness() Soundness {
	if u.BadForm != nil {
		return Error
	}
	if len(u.UnprovenMustNotFlows) > 0 {
		return Unsound
	}
	if u.CheckFeatures.isSound() && u.DataflowFeatures.isSound() {
		return Sound
	}
	return Soundy
}

func (u Unsoundness) isSound() bool {
	return len(u.UnprovenMustNotFlows) == 0 &&
		u.CheckFeatures.isSound() && u.DataflowFeatures.isSound()
}

// UnsoundCheckFeatures are the specific Go features that the function or any of its reachable
// callees may use that would make the *checking algorithm* unsound, not necessarily the data flow
// analysis.
//
// Note that this is a subset of the features that make the data flow analysis unsound.
// For example, if a reachable callee has an unbounded defers stack, the checking algorithm is sound
// as long as it doesn't need to perform an intra-procedural data flow analysis on the callee (and
// there are no other sources of unsoundness).
type UnsoundCheckFeatures struct {
	// GlobalUsages records the positions where a global is used (read/modified).
	// The analysis does not handle globals yet.
	GlobalUsages []token.Position
	// UnsafeUsages records the positions where `unsafe` is used.
	// If any reachable instruction from the function uses unsafe, then that allows arbitrary memory
	// corruption and we can no longer provide any guarantees.
	UnsafeUsages []token.Position
	// ReflectUsages records the positions where `reflect` is used.
	// The pointer analysis, which the immutability analysis depends on, is unsafe in the presence
	// of reflection.
	ReflectUsages []token.Position
	// NonLocalBoundLabelUsages records the positions of bound labels created outside their
	// corresponding MakeClosure instructions.
	// We do not support summary nodes for closure-specific inputs/outputs other than bound and free
	// variables.
	NonLocalBoundLabelUsages []token.Position
	// EntryPointUsages records the positions of entry points in the code that would be summarized by the dataflow
	// summary. This means  a dataflow analysis would potentially miss some entry points.
	EntryPointUsages []token.Position
	// TimedOut is true if the scan above did not complete before its internal timeout, so the
	// fields above may be incomplete.
	TimedOut bool
}

func (u UnsoundCheckFeatures) isSound() bool {
	return len(u.UnsafeUsages) == 0 && len(u.GlobalUsages) == 0 && len(u.ReflectUsages) == 0 &&
		len(u.NonLocalBoundLabelUsages) == 0 && len(u.EntryPointUsages) == 0 && !u.TimedOut
}

// UnsoundDataflowFeatures are the specific Go features that the function may use that would make
// the *intra-procedural data flow analysis* unsound.
//
// To avoid duplication, this does not include any unsound features that are covered by scanning for
// check-specific unsound features.
type UnsoundDataflowFeatures struct {
	RecoverUsages      []token.Position
	GoUsages           []token.Position
	HasUnboundedDefers bool
	// TimedOut is true if the intra-procedural analysis of the function or one of its
	// transitively reachable callees did not complete before the configured timeout
	// (dataflow-problems.intra-timeout-ms). When true, the computed summary may be incomplete.
	TimedOut bool
	// IntraTaintErrors records errors encountered while running the intra-procedural taint
	// analysis on transitively reachable callees while building on-demand summaries (e.g. a
	// callee too large to analyze). When non-empty, the computed summary may be incomplete, since
	// exploration stopped at the failing callee.
	IntraTaintErrors []error
}

func (u UnsoundDataflowFeatures) isSound() bool {
	return len(u.RecoverUsages) == 0 && len(u.GoUsages) == 0 && !u.HasUnboundedDefers && !u.TimedOut &&
		len(u.IntraTaintErrors) == 0
}

// Flow represents a data flow between two summary nodes.
type Flow struct {
	From summaries.SummaryNode
	To   summaries.SummaryNode
}

func newFlow(f flow) Flow {
	return Flow{
		From: newSummaryNode(f.from),
		To:   newSummaryNode(f.to),
	}
}

func (f Flow) String() string {
	return fmt.Sprintf("%s -> %s", f.From, f.To)
}

type rawSoundnessResult struct {
	Func          string
	SummaryName   string
	Want          map[string][]string
	Got           map[string][]string
	Soundness     Soundness
	Unsoundness   rawUnsoundness
	Method        string
	MethodCounts  map[string]int
	Elapsed       time.Duration
	CalleeResults [][]rawSoundnessResult
}

type rawUnsoundness struct {
	// BadForm is the string representation of Unsoundness.BadForm (nil errors serialize to an
	// empty string), since the error interface itself does not marshal to JSON.
	BadForm              string
	UnprovenMustNotFlows []string
	CheckFeatures        UnsoundCheckFeatures
	DataflowFeatures     rawUnsoundDataflowFeatures
}

// rawUnsoundDataflowFeatures is the JSON-serializable form of UnsoundDataflowFeatures: it replaces
// IntraTaintErrors ([]error, which has no exported fields to marshal) with its string
// representation via newRawUnsoundDataflowFeatures.
type rawUnsoundDataflowFeatures struct {
	RecoverUsages      []token.Position
	GoUsages           []token.Position
	HasUnboundedDefers bool
	TimedOut           bool
	IntraTaintErrors   []string
}

func newRawUnsoundDataflowFeatures(f UnsoundDataflowFeatures) rawUnsoundDataflowFeatures {
	return rawUnsoundDataflowFeatures{
		RecoverUsages:      f.RecoverUsages,
		GoUsages:           f.GoUsages,
		HasUnboundedDefers: f.HasUnboundedDefers,
		TimedOut:           f.TimedOut,
		IntraTaintErrors:   funcutil.Map(f.IntraTaintErrors, error.Error),
	}
}

func newRawSoundnessResult(r SoundnessResult) rawSoundnessResult {
	var calleeResults [][]rawSoundnessResult
	for _, crs := range r.CalleeResults {
		calleeResults = append(calleeResults, funcutil.Map(crs, newRawSoundnessResult))
	}

	methodCounts := make(map[string]int, len(r.MethodCounts))
	for m, c := range r.MethodCounts {
		methodCounts[string(m)] = c
	}

	var badForm string
	if r.Unsoundness.BadForm != nil {
		badForm = r.Unsoundness.BadForm.Error()
	}

	return rawSoundnessResult{
		Func:        r.Name,
		SummaryName: r.SummaryName,
		Want:        rawFlows(r.Want.Flows),
		Got:         rawFlows(r.Got.Flows),
		Soundness:   r.Soundness,
		Unsoundness: rawUnsoundness{
			BadForm:              badForm,
			UnprovenMustNotFlows: funcutil.Map(r.Unsoundness.UnprovenMustNotFlows, (Flow).String),
			CheckFeatures:        r.Unsoundness.CheckFeatures,
			DataflowFeatures:     newRawUnsoundDataflowFeatures(r.Unsoundness.DataflowFeatures),
		},
		Method:        string(r.Method),
		MethodCounts:  methodCounts,
		Elapsed:       r.Time,
		CalleeResults: calleeResults,
	}
}

func rawFlows(flows map[summaries.SummaryNode][]summaries.SummaryNode) map[string][]string {
	res := make(map[string][]string)
	for k, vs := range flows {
		res[k.String()] = make([]string, 0, len(vs))
		for _, v := range vs {
			res[k.String()] = append(res[k.String()], v.String())
		}
	}
	return res
}

// newSummaryNode constructs a summary node from a data flow graph node.
// Panics if gn is invalid since this should be enforced by the visitor.
func newSummaryNode(gn graphNode) summaries.SummaryNode {
	path := gn.path.String()
	switch n := gn.node.(type) {
	case *dataflow.ParamNode:
		f := n.SsaNode().Parent()
		if recv := f.Signature.Recv(); recv != nil {
			// f is a method and param is a receiver
			if n.Index() == 0 {
				return summaries.ReceiverSNode{}
			}
			return summaries.ArgumentSNode{Name: n.SsaNode().Name(), Index: n.Index() - 1, ObjectPath: path}
		}
		return summaries.ArgumentSNode{Name: n.SsaNode().Name(), Index: n.Index(), ObjectPath: path}
	case *dataflow.ReturnValNode:
		return summaries.ReturnSNode{Index: n.Index(), ObjectPath: path}
	case *dataflow.FreeVarNode:
		return summaries.FreeVarSNode{Name: n.SsaNode().Name(), ObjectPath: path}
	default:
		panic(fmt.Errorf("unexpected graph node type: %v (%T)", n, n))
	}
}

// GenerateUnsoundnessReport generates an unsoundness report with suggestions on how to fix.
//
//gocyclo:ignore
func GenerateUnsoundnessReport(state *dataflow.State) {
	var targets []dataflow.UnsoundFeaturesMap
	state.Logger.Infof("Generating unsoundness report and fix suggestions...")
	for _, g := range state.FlowGraph.Summaries {
		// Collect the summaries that have been computed (not pre-summarized and constructed) and have unsoundness
		// results. Those are the summaries the user may want to soundly pre-summarize, because they can't rely
		// on the dataflow analysis.
		if g.Unsoundness().HasAny() && g.Constructed && !g.IsPreSummarized {
			state.Logger.Debugf("Function %s has unsoundness in %+v", g.Parent.RelString(nil), g.Unsoundness())
			targets = append(targets, g.Unsoundness())
		}
	}

	toReport := map[*ssa.Function][]dataflow.UnsoundFeaturesMap{}
	// Now for each of the unsound feature maps:
	// - if the function is not in dependencies or standard library, add it to the list to report
	// - if the function is in dependencies, explore the callgraph to find the public caller ancestors
	for _, target := range targets {
		skipped := true
		f := target.Func
		fInfo, infoOk := lang.GetFunctionInfo(state.GoModInfo.Path, f)
		if (summaries.IsUserDefinedFunction(f) && fInfo.IsLocal) || fInfo.IsExported || !infoOk {
			if _, ok := toReport[f]; !ok {
				toReport[f] = []dataflow.UnsoundFeaturesMap{target}
			} else {
				toReport[f] = append(toReport[f], target)
			}
			continue
		}

		for caller := range getExportedCallers(state, f) {
			// Skip the callers that are already summarized
			if summaries.FnHasSummaries(caller) {
				continue
			}
			// Skip the functions that we shouldn't summarize
			if summaries.IsAnalysisRequired(caller) {
				continue
			}
			if _, ok := toReport[caller]; !ok {
				skipped = false
				toReport[caller] = []dataflow.UnsoundFeaturesMap{target}
			} else {
				skipped = false
				toReport[caller] = append(toReport[caller], target)
			}
		}

		if skipped {
			state.Logger.Debugf("Function %s is not exported and not in dependencies, skipping", f.RelString(nil))
		}
	}

	// Add functions that took too long to summarize
	for f := range state.SlowSummaries {
		if _, ok := toReport[f]; !ok {
			toReport[f] = nil
		}
	}

	if len(toReport) == 0 {
		state.Logger.Infof("No unsoundness found in analyzed functions")
		return
	}

	for functionToFix, unsoundnessCalleesReasons := range toReport {
		state.Logger.Warnf("Function %s should have a summary:", formatutil.Blue(functionToFix))
		if state.SlowSummaries[functionToFix] {
			state.Logger.Warnf("- it took too long to summarize")
		}
		for _, unsoundness := range unsoundnessCalleesReasons {
			if unsoundness.Func == functionToFix {
				state.Logger.Warnf("- it cannot be summarized soundly analyzed because it")
				state.Logger.Warnf("  %s", unsoundness.PrettyReason())
			} else {
				state.Logger.Warnf("- it calls %s, which cannot be soundly analyzed because it",
					unsoundness.Func.RelString(nil))
				state.Logger.Warnf("  %s", unsoundness.PrettyReason())
			}

		}
	}
}

func getExportedCallers(state *dataflow.State, f *ssa.Function) map[*ssa.Function]bool {
	callers := map[*ssa.Function]bool{}
	queue := []*ssa.Function{f}
	seen := map[*ssa.Function]bool{f: true}
	for {
		if len(queue) == 0 {
			return callers
		}
		f := queue[0]
		queue = queue[1:]
		seen[f] = true
		fInfo, infoOk := lang.GetFunctionInfo(state.GoModInfo.Path, f)
		if infoOk && fInfo.IsExported {
			callers[f] = true
			continue
		}
		for _, inEdge := range state.PointerAnalysis.CallGraph.Nodes[f].In {
			callerFunc := inEdge.Caller.Func
			if seen[callerFunc] {
				continue
			}
			queue = append(queue, callerFunc)
		}
	}
}
