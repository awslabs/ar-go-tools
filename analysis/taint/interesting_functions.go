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

package taint

import (
	"time"

	"golang.org/x/tools/go/ssa"
)

// InterestingFunctionSignals accumulates the signals observed for one function actually
// reached by taint propagation, used to determine whether it's an "interesting" method to
// summarize (see experiment/find-interesting-methods/requirements.md).
type InterestingFunctionSignals struct {
	// Unsoundness records possible sources of unsoundness of analyzing this function.
	Unsoundness []UnsoundnessKind
	// IntraTime is the intra-procedural analysis time observed for this function.
	IntraTime time.Duration
	// NumValues is the intra-procedural SSA value count observed for this function.
	NumValues int
	// IsRecursive is true if this function was reached via a recursive call (i.e., it already
	// appeared on the current calling-context stack).
	IsRecursive bool
	// ContextLosses records instances where the analysis lost calling-context information.
	// This is usually due to imprecision in the pointer analysis.
	ContextLosses []ContextLoss
	// InterfaceFanouts records instances where taint reached the call-site of an interface method
	// with many possible implementations.
	InterfaceFanouts []InterfaceFanout
}

// UnsoundnessKind is the cause of potential unsoundness in the analysis.
type UnsoundnessKind string

const (
	UnsoundnessRecovers        UnsoundnessKind = "recovers"
	UnsoundnessConcurrency     UnsoundnessKind = "concurrency"
	UnsoundnessUnboundedDefers UnsoundnessKind = "unbounded-defers"
	UnsoundnessMaxDepth        UnsoundnessKind = "max-callstack-depth"
	UnsoundnessTimeout         UnsoundnessKind = "timeout"
	UnsoundnessErr             UnsoundnessKind = "error"
)

// ContextLoss records a loss of calling-context information.
type ContextLoss struct {
	Kind   ContextLossKind // Kind is the kind of context loss.
	Degree int             // Degree is the number of instances of context loss (e.g., 5 call sites).
}

// ContextLossKind is the kind of context loss.
type ContextLossKind string

const (
	ContextLossCallSites    ContextLossKind = "call-sites"
	ContextLossClosureSites ContextLossKind = "closure-sites"
	ContextLossGlobalReads  ContextLossKind = "global-reads"
)

// InterfaceFanout records when an interface method has many implementations.
type InterfaceFanout struct {
	InterfacePackage string // InterfacePackage is the fully-qualified package name (e.g., fmt).
	InterfaceName    string // InterfaceName is the name of the interface (e.g., Stringer).
	MethodName       string // MethodName is the name of the interface method (e.g., String).
	NumImpls         int    // NumImpls is the number of concrete implementations of the interface.
	Callsite         string // Callsite is the source position of the call site (file:line:col).
}

// InterestingFunctions maps each function reached by taint propagation to the signals recorded
// for it.
type InterestingFunctions map[*ssa.Function]*InterestingFunctionSignals

// signalsFor returns the signals for f, creating a new entry if this is the first time f is
// reached.
func (m InterestingFunctions) signalsFor(f *ssa.Function) *InterestingFunctionSignals {
	sig, ok := m[f]
	if !ok {
		sig = &InterestingFunctionSignals{}
		m[f] = sig
	}
	return sig
}
