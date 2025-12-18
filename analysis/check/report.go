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
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// SoundnessResult is the result of checking the soundness of a single data flow summary.
type SoundnessResult struct {
	// Fn is the qualified name of the summarized function.
	Fn string
	// Want is the summary being checked.
	Want summaries.DetailedSummary
	// IsSound is true if there is no unsoundness.
	IsSound bool
	// Unsoundness is the potential sources of unsoundness in the soundness check.
	// IsSound is false if there is any unsoundness.
	Unsoundness Unsoundness
	// Method is the least powerful method needed to be used for the soundness check.
	Method Method
	// Time is the time spent to calculate the result.
	Time time.Duration
	// CalleeResults are the soundness results of the callees.
	// It's a slice of slices because there may be multiple inferred callee summaries.
	CalleeResults [][]SoundnessResult
}

func (r SoundnessResult) String() string {
	b, err := r.MarshalJSON()
	if err != nil {
		panic(fmt.Errorf("failed to marshal soundness result for function %s to JSON: %v", r.Fn, err))
	}

	return string(b)
}

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
	// UnprovenMustNotFlows are the must-not-flows unable to be proven.
	UnprovenMustNotFlows []Flow
	// CheckFeatures are the unsound features that make the checking algorithm unsound.
	CheckFeatures UnsoundCheckFeatures
	// DataflowFeatures are the unsound features that make the data flow analysis unsound.
	DataflowFeatures UnsoundDataflowFeatures
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
	// UnsafeUsages records the positions where `unsafe` is used.
	// If any reachable instruction from the function uses unsafe, then that allows arbitrary memory
	// corruption and we can no longer provide any guarantees.
	UnsafeUsages []token.Position
	// GoUsages records the positions where a goroutine is created.
	// The checking algorithm assumes linearizability of instructions which is potentially violated
	// in the presence of parallelism via goroutines.
	GoUsages []token.Position
	// GlobalUsages records the positions where a global is used (read/modified).
	// The analysis does not handle globals yet.
	GlobalUsages []token.Position
}

func (u UnsoundCheckFeatures) isSound() bool {
	return len(u.UnsafeUsages) == 0 && len(u.GoUsages) == 0 && len(u.GlobalUsages) == 0
}

// UnsoundDataflowFeatures are the specific Go features that the function may use that would make
// the *intra-procedural data flow analysis* unsound.
//
// To avoid duplication, this does not include any unsound features that are covered by scanning for
// check-specific unsound features.
type UnsoundDataflowFeatures struct {
	RecoverUsages      []token.Position
	ReflectUsages      []token.Position
	HasUnboundedDefers bool
}

func newUnsoundDataflowFeatures(feats dataflow.UnsoundFeaturesMap) UnsoundDataflowFeatures {
	return UnsoundDataflowFeatures{
		RecoverUsages:      maps.Keys(feats.Recovers),
		ReflectUsages:      maps.Keys(feats.ReflectUsages),
		HasUnboundedDefers: feats.HasUnboundedDefers,
	}
}

func (u UnsoundDataflowFeatures) isSound() bool {
	return len(u.RecoverUsages) == 0 && len(u.ReflectUsages) == 0 && !u.HasUnboundedDefers
}

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
	Want          map[string][]string
	IsSound       bool
	Unsoundness   rawUnsoundness
	Method        string
	TimeSeconds   time.Duration
	CalleeResults [][]rawSoundnessResult
}

type rawUnsoundness struct {
	UnprovenMustNotFlows []string
	CheckFeatures        UnsoundCheckFeatures
	DataflowFeatures     UnsoundDataflowFeatures
}

func newRawSoundnessResult(r SoundnessResult) rawSoundnessResult {
	var calleeResults [][]rawSoundnessResult
	for _, crs := range r.CalleeResults {
		calleeResults = append(calleeResults, funcutil.Map(crs, newRawSoundnessResult))
	}

	return rawSoundnessResult{
		Func:    r.Fn,
		Want:    rawFlows(r.Want.Flows),
		IsSound: r.IsSound,
		Unsoundness: rawUnsoundness{
			UnprovenMustNotFlows: funcutil.Map(r.Unsoundness.UnprovenMustNotFlows, (Flow).String),
			CheckFeatures:        r.Unsoundness.CheckFeatures,
			DataflowFeatures:     r.Unsoundness.DataflowFeatures,
		},
		Method:        string(r.Method),
		TimeSeconds:   time.Duration(r.Time.Seconds()),
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
func newSummaryNode(gn dataflow.GraphNode) summaries.SummaryNode {
	switch gn := gn.(type) {
	case *dataflow.ParamNode:
		f := gn.SsaNode().Parent()
		if recv := f.Signature.Recv(); recv != nil {
			// f is a method and param is a receiver
			if gn.Index() == 0 {
				return summaries.ReceiverSNode{}
			}
			return summaries.ArgumentSNode{Name: gn.SsaNode().Name(), Index: gn.Index() - 1, ObjectPath: ""}
		}
		return summaries.ArgumentSNode{Name: gn.SsaNode().Name(), Index: gn.Index(), ObjectPath: ""}
	case *dataflow.ReturnValNode:
		return summaries.ReturnSNode{Index: gn.Index(), ObjectPath: ""}
	case *dataflow.FreeVarNode:
		return summaries.FreeVarSNode{Name: gn.SsaNode().Name()}
	default:
		panic(fmt.Errorf("unexpected graph node type: %v (%T)", gn, gn))
	}
}

// GenerateUnsoundnessReport generates an unsoundness report with suggestions on how to fix.
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
				skipped = false
				toReport[f] = []dataflow.UnsoundFeaturesMap{target}
			} else {
				skipped = false
				toReport[f] = append(toReport[f], target)
			}
			continue
		}

		for _, caller := range getExportedCallers(state, f) {
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

	for functionToFix, unsoundnessCalleesReasons := range toReport {
		state.Logger.Warnf("Function %s should have a summary:", functionToFix)
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

func getExportedCallers(state *dataflow.State, f *ssa.Function) []*ssa.Function {
	var callers []*ssa.Function
	queue := []*ssa.Function{f}
	seen := map[*ssa.Function]bool{f: true}
	for {
		if len(queue) == 0 {
			return callers
		}
		f := queue[0]
		queue = queue[1:]
		for _, caller := range state.PointerAnalysis.CallGraph.Nodes[f].In {
			callerFunc := caller.Caller.Func
			if seen[callerFunc] {
				continue
			}
			seen[callerFunc] = true
			callerInfo, infoOk := lang.GetFunctionInfo(state.GoModInfo.Path, callerFunc)
			if callerInfo.IsExported || !infoOk {
				callers = append(callers, callerFunc)
			} else {
				queue = append(queue, callerFunc)
			}
		}
	}
}
