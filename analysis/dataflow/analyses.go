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

package dataflow

import "golang.org/x/tools/go/ssa"

// EscapeAnalysisState defines a lightweight interface to allow the dataflow AnalyzerState to store the escape analysis
// state.
type EscapeAnalysisState interface {
	IsEscapeAnalysisState() bool
	InitialGraphs() map[*ssa.Function]EscapeGraph
}

type EscapeGraph interface {
	ComputeInstructionLocality(prog EscapeAnalysisState, f *ssa.Function) map[ssa.Instruction]bool
	ComputeCallsiteGraph(prog EscapeAnalysisState,
		caller *ssa.Function, call *ssa.Call, callee *ssa.Function) EscapeGraph
	ComputeArbitraryCallerGraph(prog EscapeAnalysisState, f *ssa.Function) EscapeGraph
	IMerge(EscapeGraph)
	IClone() EscapeGraph
}
