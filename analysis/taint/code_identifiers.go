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
	"go/token"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/go/ssa"
)

// IsSomeSourceNode returns true if n matches the code identifier of some source in the config
func IsSomeSourceNode(cfg *config.Config, n ssa.Node) bool {
	return analysisutil.IsEntrypointNode(n, cfg.IsSomeSource)
}

// IsSourceNode returns true if n matches the code identifier of a source node in the taint specification
func IsSourceNode(ts *config.TaintSpec, n ssa.Node) bool {
	return analysisutil.IsEntrypointNode(n, ts.IsSource)
}

func isSink(ts *config.TaintSpec, n dataflow.GraphNode) bool {
	return isMatchingCodeId(ts.IsSink, n)
}

func isSanitizer(ts *config.TaintSpec, n dataflow.GraphNode) bool {
	return isMatchingCodeId(ts.IsSanitizer, n)
}

// isValidatorCondition checks whether v is a validator condition according to the validators stored in the config
// This function makes recursive calls on the value if necessary.
func isValidatorCondition(ts *config.TaintSpec, v ssa.Value, isPositive bool) bool {
	switch val := v.(type) {
	// Direct boolean check?
	case *ssa.Call:
		return isPositive && isMatchingCodeIdWithCallee(ts.IsValidator, nil, val)
	// Nil error check?
	case *ssa.BinOp:
		vNilChecked, isEqCheck := lang.MatchNilCheck(val)
		// Validator condition holds on the branch where "not err != nil" or "err == nil"
		// i.e. if not positive and not isEqCheck or positive and isEqCheck
		return (isPositive == isEqCheck) && isValidatorCondition(ts, vNilChecked, true)
	case *ssa.UnOp:
		if val.Op == token.NOT {
			// Validator condition must hold on the negated value, with the negated positive condition
			return isValidatorCondition(ts, val.X, !isPositive)
		}
	case *ssa.Extract:
		// Validator condition must hold on the tuple result
		return isValidatorCondition(ts, val.Tuple, isPositive)
	}
	return false
}

func isFiltered(ts *config.TaintSpec, n dataflow.GraphNode) bool {
	for _, filter := range ts.Filters {
		if filter.Type != "" {
			if filter.MatchType(n.Type()) {
				return true
			}
		}
		var f *ssa.Function
		switch n2 := n.(type) {
		case *dataflow.CallNode:
			f = n2.Callee()
		case *dataflow.CallNodeArg:
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

func isMatchingCodeId(codeIdOracle func(config.CodeIdentifier) bool, n dataflow.GraphNode) bool {
	switch n := n.(type) {
	case *dataflow.ParamNode, *dataflow.FreeVarNode:
		// A these nodes are never a sink; the sink will be identified at the call site, not the callee definition.
		return false
	case *dataflow.CallNodeArg:
		// A call node argument is a sink if the callee is a sink
		if isMatchingCodeId(codeIdOracle, n.ParentNode()) {
			return true
		}

		// The matching parameter node could be a sink
		callSite := n.ParentNode()
		if callSite == nil {
			return false
		}
		if callSite.CalleeSummary == nil {
			panic("nil callsite summary")
		}
		param := callSite.CalleeSummary.Parent.Params[n.Index()]
		if param == nil {
			return false
		}
		return isMatchingCodeIdWithCallee(codeIdOracle, callSite.CalleeSummary.Parent, param.Parent())
	case *dataflow.CallNode:
		return isMatchingCodeIdWithCallee(codeIdOracle, n.Callee(), n.CallSite().(ssa.Node))
	case *dataflow.SyntheticNode:
		return isMatchingCodeIdWithCallee(codeIdOracle, nil, n.Instr().(ssa.Node)) // safe type conversion
	case *dataflow.ReturnValNode, *dataflow.ClosureNode, *dataflow.BoundVarNode:
		return false
	default:
		return false
	}
}

// isMatchingCodeIdWIthCallee returns true when the codeIdOracle returns true for a code identifier matching the node
// n in the context where callee is the callee
func isMatchingCodeIdWithCallee(codeIdOracle func(config.CodeIdentifier) bool, callee *ssa.Function, n ssa.Node) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered sinks
	case *ssa.Call, *ssa.Go, *ssa.Defer:
		// This condition should always be true
		if callNode, ok := node.(ssa.CallInstruction); ok {
			callCommon := callNode.Common()
			if callCommon.IsInvoke() {
				receiver := callCommon.Value.Name()
				methodName := callCommon.Method.Name()
				maybePkg := analysisutil.FindSafeCalleePkg(callCommon)
				if maybePkg.IsSome() {
					return codeIdOracle(config.CodeIdentifier{
						Package: maybePkg.Value(), Method: methodName, Receiver: receiver,
					})
				} else if callee != nil {
					pkgName := lang.PackageNameFromFunction(callee)
					return codeIdOracle(config.CodeIdentifier{
						Package: pkgName, Method: methodName, Receiver: receiver,
					})
				} else {
					return false
				}
			} else {
				funcName := callCommon.Value.Name()
				maybePkg := analysisutil.FindSafeCalleePkg(callCommon)
				if maybePkg.IsSome() {
					return codeIdOracle(config.CodeIdentifier{Package: maybePkg.Value(), Method: funcName})
				} else if callee != nil {
					pkgName := lang.PackageNameFromFunction(callee)
					return codeIdOracle(config.CodeIdentifier{
						Package: pkgName, Method: funcName,
					})
				} else {
					return false
				}
			}
		}
		return false
	case *ssa.Function:
		return codeIdOracle(config.CodeIdentifier{
			Package: lang.PackageNameFromFunction(node),
			Method:  node.Name(),
		})
	// We will likely extend the functionality to other types of sanitizers
	default:
		return false
	}
}
