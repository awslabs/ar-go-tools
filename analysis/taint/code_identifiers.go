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

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

func IsSourceNode(cfg *config.Config, n ssa.Node) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered sources
	case *ssa.Call:
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg := dataflow.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return cfg.IsSource(config.CodeIdentifier{Package: calleePkg.Value(), Method: methodName, Receiver: receiver})
			} else {
				return false
			}
		} else {
			funcValue := node.Call.Value.Name()
			calleePkg := dataflow.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return cfg.IsSource(config.CodeIdentifier{Package: calleePkg.Value(), Method: funcValue})
			} else {
				return false
			}
		}

	// Field accesses that are considered as sources
	case *ssa.Field:
		fieldName := dataflow.FieldFieldName(node)
		packageName, typeName, err := dataflow.FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return cfg.IsSource(config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	case *ssa.FieldAddr:
		fieldName := dataflow.FieldAddrFieldName(node)
		packageName, typeName, err := dataflow.FindTypePackage(node.X.Type())
		if err != nil {
			return false
		} else {
			return cfg.IsSource(config.CodeIdentifier{Package: packageName, Field: fieldName, Type: typeName})
		}

	// Allocations of data of a type that is a source
	case *ssa.Alloc:
		packageName, typeName, err := dataflow.FindTypePackage(node.Type())
		if err != nil {
			return false
		} else {
			return cfg.IsSource(config.CodeIdentifier{Package: packageName, Type: typeName})
		}

	default:
		return false
	}
}

func isSource(n dataflow.GraphNode, cfg *config.Config) bool {
	switch n := n.(type) {
	case *dataflow.CallNode:
		return IsSourceNode(cfg, n.CallSite().(ssa.Node)) // safe type conversion
	case *dataflow.SyntheticNode:
		return IsSourceNode(cfg, n.Instr().(ssa.Node)) // safe type conversion
	default:
		return false
	}
}

func IsSinkNode(cfg *config.Config, n ssa.Node) bool {
	return isMatchingCodeIdWithCallee(cfg.IsSink, nil, n)
}

func isSink(n dataflow.GraphNode, cfg *config.Config) bool {
	return isMatchingCodeId(cfg.IsSink, n)
}

func isSanitizer(n dataflow.GraphNode, cfg *config.Config) bool {
	return isMatchingCodeId(cfg.IsSanitizer, n)
}

// isValidatorCondiiton checks whether v is a validator condition according to the validators stored in the config
// This function recurses on the value if necessary.
func isValidatorCondition(isPositive bool, v ssa.Value, cfg *config.Config) bool {
	switch val := v.(type) {
	// Direct boolean check?
	case *ssa.Call:
		return isPositive && isMatchingCodeIdWithCallee(cfg.IsValidator, nil, val)
	// Nil error check?
	case *ssa.BinOp:
		vNilChecked, isEqCheck := lang.MatchNilCheck(val)
		// Validator condition holds on the branch where "not err != nil" or "err == nil"
		// i.e. if not positive and not isEqCheck or positive and isEqCheck
		return (isPositive == isEqCheck) && isValidatorCondition(true, vNilChecked, cfg)
	case *ssa.UnOp:
		if val.Op == token.NOT {
			// Validator condition must hold on the negated value, with the negated positive condition
			return isValidatorCondition(!isPositive, val.X, cfg)
		}
	case *ssa.Extract:
		// Validator condition must hold on the tuple result
		return isValidatorCondition(isPositive, val.Tuple, cfg)
	}
	return false
}

func isFiltered(n dataflow.GraphNode, cfg *config.Config) bool {
	for _, filter := range cfg.Filters {
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
		return isMatchingCodeId(codeIdOracle, n.ParentNode())
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

// isMatchingCodeIdWIthCallee returns true when the codeIdOracle returns true for a code identifier maching the node
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
				maybePkg := dataflow.FindSafeCalleePkg(callCommon)
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
				maybePkg := dataflow.FindSafeCalleePkg(callCommon)
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
	// We will likely extend the functionality to other types of sanitizers
	default:
		return false
	}
}
