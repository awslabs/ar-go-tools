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

// EscapeAnalysisState Represents the state required to answer queries for a particular program. Internally, holds
// the escape summaries of each analyzed `ssa.Function`. Summaries are bottom-up, but useful
// locality information requires tracking information from callers (e.g. whether a particular
// argument is allocated locally). Rather than baking in a particular context-sensitivity, this
// interface gives the client the ability to control how context-sensitivity is handled. In
// particular, an EscapeCallContext encodes information about the calling context, as it is
// relevant to locality.
//
// This calling context can be used to compute the instruction locality, defined as whether
// each instruction only manipulates local information, for a particular function.
// This process also computes, for each callsite in a function, the context the callee
// will be called under, assuming that edge is traversed. (These operations are combined because
// they use an identical, expensive monotone convergence loop internally.) The callsite information
// is initially a `EscapeCallsiteInfo`, which is generic for all callees. It can be resolved into
// a EscapeCallContext for a particular specific callee function. Effectively, an EscapeCallsiteInfo
// represents the context from the callers perspective, whereas the EscapeCallContext represents the
// same info from the callee's perspective.
//
// The `Merge()` operation on a EscapeCallContext can be used to avoid a blowup in the number of
// contexts. Merging multiple contexts is monotone, and the `Matches()` method can be used to detect
// convergence in the presence of recursive functions. (Note, the context returned by
// ComputeArbitraryContext is not a unit of Merge; it should not be used to initialize a convergence loop.)
type EscapeAnalysisState interface {
	// IsEscapeAnalysisState ensures only the escape analysis implements this interface. Returns true.
	IsEscapeAnalysisState() bool
	// IsSummarized returns whether the escape analysis has a summary for f
	IsSummarized(f *ssa.Function) bool
	// ComputeArbitraryContext  computes a call context for f assuming it could be called from anywhere.
	// This is conservative, and
	// will result in less locality than if a correct call context is provided. If there are no arguments
	// (such as for main), then there is no loss of precision.
	ComputeArbitraryContext(f *ssa.Function) EscapeCallContext
	// ComputeInstructionLocalityAndCallsites computes locality and callsite information for a function,
	// given a particular calling context.
	// This internally performs a potentially expensive flow-sensitive monotone convergence loop. The
	// resulting locality map contains a true value for each instruction that is provably local, and false
	// for instructions that may access shared memory. The callsite infos must be resolved for each
	// possible concrete callee; see `EscapeCallsiteInfo.Resolve()`. Only calls to non-builtins are
	// available in `callsiteInfo`.
	ComputeInstructionLocalityAndCallsites(f *ssa.Function, ctx EscapeCallContext) (
		instructionLocality map[ssa.Instruction]*EscapeRationale,
		callsiteInfo map[ssa.CallInstruction]EscapeCallsiteInfo)

	ParameterPostEscape(EscapeCallContext) []*EscapeRationale
}

// EscapeCallContext represents the escape-relevant context for a particular `ssa.Function`.
// Can be merged with another context for the same function and compared.
// `EscapeCallContext`s are specific to a particular ssa.Function; they cannot
// be shared even amongst functions with the same signature.
// EscapeCallContext objects are immutable.
type EscapeCallContext interface {
	// Merge returns a new EscapeCallContext that is the merge of `this` and `other`,
	// and whether the result is semantically different from `this`.
	Merge(other EscapeCallContext) (changed bool, merged EscapeCallContext)
	// Matches returns true if the two calling contexts are semantically equivalent.
	Matches(EscapeCallContext) bool
	// ParameterEscape returns whether each parameter has escaped, via a non-nil EscapeRationale
	ParameterEscape() []*EscapeRationale
}

// EscapeCallsiteInfo represents a call context, but from the caller's perspective at a particular
// callsite. This information doesn't depend on the particular callee (e.g. the
// implementation of an interface call), but may be `Resolve`d for a particular
// callee. EscapeCallsiteInfo objects are immutable.
type EscapeCallsiteInfo interface {
	Resolve(callee *ssa.Function) EscapeCallContext
	// Graph returns the graphviz of the callsite escape graph
	Graph() string
}

// EscapeRationale holds information on the rationale of why a value may escape
type EscapeRationale struct {
	Reason string
	// For more informative rationales, this can include a trace showing the steps along the way.
	// For now, we just store the ultimate "base" reason why something leaks (global, function, go, etc).
}

func (r *EscapeRationale) String() string {
	return r.Reason
}

// NewBaseRationale returns a new escape rationale with the reason provided as argument
func NewBaseRationale(reason string) *EscapeRationale {
	return &EscapeRationale{Reason: reason}
}
