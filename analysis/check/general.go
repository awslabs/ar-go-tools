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
	"time"

	"golang.org/x/tools/go/ssa"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// checkSummaryMostGeneral checks the soundness of want by comparing it to the most-general summary
// of f.
// The most-general summary assumes that all function inputs (parameters) flow to all function
// outputs (parameters and all return values).
// If useTypes is true, then non-pointer-like inputs are not considered to be outputs.
func checkSummaryMostGeneral(
	f *ssa.Function, want summaries.DetailedSummary, start time.Time, useTypes bool,
) (SoundnessResult, error) {
	got := newMostGeneralDetailedSummary(f, useTypes)
	end := time.Since(start)
	fname := f.RelString(nil)
	isSound, badFlows := isSummarySubset(fname, want, got)

	return SoundnessResult{
		Fn:       fname,
		Want:     want,
		Got:      got,
		IsSound:  isSound,
		BadFlows: badFlows,
		Time:     end,
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
