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

	"github.com/awslabs/ar-go-tools/analysis/annotations"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
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
	return analysisutil.IsEntrypointNode(state.PointerAnalysis, n, state.Config.IsSomeSource) ||
		analysisutil.IsEntrypointNode(state.PointerAnalysis, n, state.Config.IsSomeSink) ||
		analysisutil.IsEntrypointNode(state.PointerAnalysis, n, state.Config.IsSomeBacktracePoint) ||
		state.ResolveSsaNode(annotations.Source, "_", n) ||
		state.ResolveSsaNode(annotations.Sink, "_", n)
}

// IsSourceNode returns true if n matches the code identifier of a source node in the taint specification.
// If the taint specification is nil, then it will look whether the node can be any source node in the
// config.
func IsSourceNode(state *State, ts *config.TaintSpec, n ssa.Node) bool {
	if ts == nil {
		return analysisutil.IsEntrypointNode(state.PointerAnalysis, n, state.Config.IsSomeSource) ||
			state.ResolveSsaNode(annotations.Source, "_", n)
	}
	return analysisutil.IsEntrypointNode(state.PointerAnalysis, n, ts.IsSource) ||
		state.ResolveSsaNode(annotations.Source, ts.Tag, n)
}

// IsBacktraceNode returns true if slicing spec identifies n as a backtrace entrypoint. If the backtrace specification
// is nil, then it will look at whether the node can be any backtrace point in the config.
func IsBacktraceNode(state *State, ss *config.SlicingSpec, n ssa.Node) bool {
	if f, ok := n.(*ssa.Function); ok {
		pkg := lang.PackageNameFromFunction(f)
		return ss.IsBacktracePoint(config.CodeIdentifier{Package: pkg, Method: f.Name()})
	}

	if ss == nil {
		return analysisutil.IsEntrypointNode(state.PointerAnalysis, n, state.Config.IsSomeBacktracePoint)
	}
	return analysisutil.IsEntrypointNode(state.PointerAnalysis, n, ss.IsBacktracePoint)
}

// IsSink returns true if the taint spec identifies n as a sink.
func IsSink(state *State, ts *config.TaintSpec, n GraphNode) bool {
	return isMatchingCodeID(ts.IsSink, n) || state.ResolveGraphNode(annotations.Sink, ts.Tag, n)
}

// IsSanitizer returns true if the taint spec identified n as a sanitizer.
func IsSanitizer(state *State, ts *config.TaintSpec, n GraphNode) bool {
	return isMatchingCodeID(ts.IsSanitizer, n) || state.ResolveGraphNode(annotations.Sanitizer, ts.Tag, n)
}

// IsValidatorCondition checks whether v is a validator condition according to the validators stored in the taint
// analysis specification.
// This function makes recursive calls on the value if necessary.
func IsValidatorCondition(ts *config.TaintSpec, v ssa.Value, isPositive bool) bool {
	switch val := v.(type) {
	// Direct boolean check?
	case *ssa.Call:
		return isPositive && IsMatchingCodeIDWithCallee(ts.IsValidator, nil, val)
	// Nil error check?
	case *ssa.BinOp:
		vNilChecked, isEqCheck := lang.MatchNilCheck(val)
		// Validator condition holds on the branch where "not err != nil" or "err == nil"
		// i.e. if not positive and not isEqCheck or positive and isEqCheck
		return (isPositive == isEqCheck) && IsValidatorCondition(ts, vNilChecked, true)
	case *ssa.UnOp:
		if val.Op == token.NOT {
			// Validator condition must hold on the negated value, with the negated positive condition
			return IsValidatorCondition(ts, val.X, !isPositive)
		}
	case *ssa.Extract:
		// Validator condition must hold on the tuple result
		return IsValidatorCondition(ts, val.Tuple, isPositive)
	}
	return false
}

// IsFiltered returns true if the node is filtered out by the taint analysis.
func IsFiltered(s *State, ts *config.TaintSpec, n GraphNode) bool {
	for _, filter := range ts.Filters {
		if filter.Type != "" {
			if filter.MatchType(n.Type()) {
				return true
			}
		}
		var f *ssa.Function
		switch n2 := n.(type) {
		case *CallNode:
			f = n2.Callee()
		case *CallNodeArg:
			f = n2.ParentNode().Callee()
		}
		if f != nil && filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}
	return false
}

func isMatchingCodeID(codeIDOracle func(config.CodeIdentifier) bool, n GraphNode) bool {
	switch n := n.(type) {
	case *ParamNode, *FreeVarNode:
		// A these nodes are never a sink; the sink will be identified at the call site, not the callee definition.
		return false
	case *CallNodeArg:
		// A call node argument is a sink if the callee is a sink
		if isMatchingCodeID(codeIDOracle, n.ParentNode()) {
			return true
		}

		// The matching parameter node could be a sink
		callSite := n.ParentNode()
		if callSite == nil {
			return false
		}
		if callSite.CalleeSummary == nil {
			return false
		}
		param := callSite.CalleeSummary.Parent.Params[n.Index()]
		if param == nil {
			return false
		}
		return IsMatchingCodeIDWithCallee(codeIDOracle, callSite.CalleeSummary.Parent, param.Parent())
	case *CallNode:
		return IsMatchingCodeIDWithCallee(codeIDOracle, n.Callee(), n.CallSite().(ssa.Node))
	case *BuiltinCallNode:
		return codeIDOracle(config.CodeIdentifier{Context: n.parent.Parent.String(), Method: n.name})
	case *SyntheticNode:
		return analysisutil.IsEntrypointNode(nil, n.Instr().(ssa.Node), codeIDOracle)
	case *ReturnValNode, *ClosureNode, *BoundVarNode:
		return false
	default:
		return false
	}
}

// IsMatchingCodeIDWithCallee returns true when the codeIdOracle returns true for a code identifier matching the node
// n in the context where callee is the callee.
func IsMatchingCodeIDWithCallee(codeIDOracle func(config.CodeIdentifier) bool, callee *ssa.Function, n ssa.Node) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered sinks
	case *ssa.Call, *ssa.Go, *ssa.Defer:
		// This condition should always be true
		callNode, ok := node.(ssa.CallInstruction)
		if !ok {
			return false
		}
		callCommon := callNode.Common()
		// Handling interfaces
		if callCommon.IsInvoke() {
			receiverType := callCommon.Value.Type().String()
			methodName := callCommon.Method.Name()
			maybePkg := analysisutil.FindSafeCalleePkg(callCommon)
			if maybePkg.IsSome() {
				cid := config.CodeIdentifier{
					Context:    node.Parent().String(),
					Package:    maybePkg.Value(),
					Method:     methodName,
					Receiver:   receiverType,
					ValueMatch: n.String(),
				}
				return codeIDOracle(cid)
			}
			if callee != nil {
				pkgName := lang.PackageNameFromFunction(callee)
				cid := config.CodeIdentifier{
					Context:    node.Parent().String(),
					Package:    pkgName,
					Method:     methodName,
					Receiver:   receiverType,
					ValueMatch: n.String(),
				}
				return codeIDOracle(cid)
			}
			return false
		}

		funcName := callCommon.Value.Name()
		receiverType := ""
		if callCommon.Signature() != nil && callCommon.Signature().Recv() != nil {
			receiverType = analysisutil.ReceiverStr(callCommon.Signature().Recv().Type())
		}
		maybePkg := analysisutil.FindSafeCalleePkg(callCommon)
		if maybePkg.IsSome() {
			cid := config.CodeIdentifier{
				Context:    node.Parent().String(),
				Package:    maybePkg.Value(),
				Method:     funcName,
				Receiver:   receiverType,
				ValueMatch: n.String(),
			}
			return codeIDOracle(cid)
		}
		if callee != nil {
			pkgName := lang.PackageNameFromFunction(callee)
			cid := config.CodeIdentifier{
				Context:    node.Parent().String(),
				Package:    pkgName,
				Method:     funcName,
				Receiver:   receiverType,
				ValueMatch: n.String(),
			}
			return codeIDOracle(cid)
		}
		return false

	case *ssa.Function:
		return codeIDOracle(config.CodeIdentifier{
			Package:    lang.PackageNameFromFunction(node),
			Method:     node.Name(),
			ValueMatch: n.String(),
		})
	// We will likely extend the functionality to other types of sanitizers
	default:
		return false
	}
}
