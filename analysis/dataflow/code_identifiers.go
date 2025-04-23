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

import (
	"go/token"
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/annotations"
	"github.com/awslabs/ar-go-tools/analysis/config/specs"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/scanning"
	"golang.org/x/tools/go/ssa"
)

// IsNodeOfInterest returns true when the node should appear in the dataflow graph.
// This is usually automatically the case for all the callgraph nodes (calls, returns, parameters, arguments) but not
// the case for all the synthetic nodes.
// This function is usually used in the intra-procedural analysis as the function to identify what SSA nodes to add.
// It should identify all the "synthetic" nodes, i.e.:
// - reading from struct fields that are marked as sources.
// - reading from channels marked as source
// - writing in struct fields that are marked as sinks.
func IsNodeOfInterest(state *State, n ssa.Node) bool {
	nc := scanning.NewSsaNodeCode(n)
	if state.Config.IsSomeSource(state.PointerAnalysis, nc) ||
		state.Config.IsSomeSink(state.PointerAnalysis, nc) ||
		state.Config.IsSomeSanitizer(state.PointerAnalysis, nc) ||
		state.Config.IsSomeBacktracePoint(state.PointerAnalysis, nc) {
		return true
	}

	return state.ResolveSsaNode(annotations.Source, "_", n) || state.ResolveSsaNode(annotations.Sink, "_", n)
}

// IsSourceNode returns true if n matches the code identifier of a source node in the taint specification.
// If the taint specification is nil, then it will look whether the node can be any source node in the
// config.
func IsSourceNode(state *State, ts *specs.Taint, n ssa.Node) bool {
	nc := scanning.NewSsaNodeCode(n)
	if ts == nil {
		if state.Config.IsSomeSource(state.PointerAnalysis, nc) {
			return true
		}
		return state.ResolveSsaNode(annotations.Source, "_", n)
	}
	return ts.IsSource(state.PointerAnalysis, nc) ||
		state.ResolveSsaNode(annotations.Source, ts.Tag, n)
}

// IsSink returns true if the taint spec identifies n as a sink.
func IsSink(state *State, ts *specs.Taint, n GraphNode) bool {
	return ts.IsSink(state.PointerAnalysis, n.SsaCode()) ||
		state.ResolveGraphNode(annotations.Sink, ts.Tag, n)
}

// IsSanitizer returns true if the taint spec identified n as a sanitizer.
func IsSanitizer(state *State, ts *specs.Taint, n GraphNode) bool {
	return ts.IsSanitizer(state.PointerAnalysis, n.SsaCode()) ||
		state.ResolveGraphNode(annotations.Sanitizer, ts.Tag, n)
}

// IsValidatorCondition checks whether v is a validator condition according to the validators stored in the taint
// analysis specification.
// This function makes recursive calls on the value if necessary.
func IsValidatorCondition(state *State, ts *specs.Taint, v ssa.Value, isPositive bool) bool {
	if ts == nil {
		return false
	}
	switch val := v.(type) {
	// Direct boolean check?
	case *ssa.Call:
		return isPositive && ts.IsValidator(state.PointerAnalysis, scanning.NewValueCode(v, false))
	// Nil error check?
	case *ssa.BinOp:
		vNilChecked, isEqCheck := lang.MatchNilCheck(val)
		// Validator condition holds on the branch where "not err != nil" or "err == nil"
		// i.e. if not positive and not isEqCheck or positive and isEqCheck
		return (isPositive == isEqCheck) && IsValidatorCondition(state, ts, vNilChecked, true)
	case *ssa.UnOp:
		if val.Op == token.NOT {
			// Validator condition must hold on the negated value, with the negated positive condition
			return IsValidatorCondition(state, ts, val.X, !isPositive)
		}
	case *ssa.Extract:
		// Validator condition must hold on the tuple result
		return IsValidatorCondition(state, ts, val.Tuple, isPositive)
	}
	return false
}

// IsFiltered returns true if the node is filtered out by the taint analysis.
func IsFiltered(s *State, ts *specs.Taint, n GraphNode) bool {
	if ts == nil {
		return false
	}
	return ts.IsFiltered(s.PointerAnalysis, n.SsaCode())
}

// IsFilteredType returns true if the type is filtered out by the taint analysis specification.
func IsFilteredType(ts *specs.Taint, t types.Type) bool {
	for _, filter := range ts.ParsedTaintSpec.Filters {
		if filter.Type != "" {
			if filter.MatchType(t) {
				return true
			}
		}
	}
	return false
}
