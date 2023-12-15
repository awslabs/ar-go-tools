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

// Package analysisutil contains utility functions for the analyses in argot.
// These functions are in an internal package because they are not important
// enough to be included in the main library.
package analysisutil

import (
	"fmt"
	"go/token"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/capabilities"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// EntrypointParams represents the parameters to IsEntrypointNode.
type EntrypointParams struct {
	Pointer        *pointer.Result
	Classifier     *capabilities.DefaultClassifier
	InterfaceImpls map[string]map[*ssa.Function]bool
	CodeIDOracle   func(config.CodeIdentifier) bool
}

// IsEntrypointNode returns true if n is an entrypoint to the analysis according to params.CodeIDOracle.
func IsEntrypointNode(params EntrypointParams, n ssa.Node) bool {
	f := params.CodeIDOracle
	switch node := (n).(type) {
	// Look for callees to functions that are considered entry points
	case *ssa.Call:
		if node == nil {
			return false // inits cannot be entry points
		}

		parent := node.Parent()
		if node.Call.IsInvoke() {
			return isInterfaceEntrypoint(params, node, parent)
		}

		return isFuncEntrypoint(params, node, parent) || isAliasEntrypoint(params, node, parent)

	// Field accesses that are considered as entry points
	case *ssa.Field:
		fieldName := lang.FieldFieldName(node)
		packageName, typeName, err := lang.FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context: node.Parent().String(),
			Package: packageName,
			Field:   fieldName,
			Type:    typeName})

	case *ssa.FieldAddr:
		fieldName := lang.FieldAddrFieldName(node)
		packageName, typeName, err := lang.FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context: node.Parent().String(),
			Package: packageName,
			Field:   fieldName,
			Type:    typeName})

	// Allocations of data of a type that is an entry point
	case *ssa.Alloc:
		packageName, typeName, err := lang.FindEltTypePackage(node.Type(), "%s")
		if err != nil {
			return false
		}
		return f(config.CodeIdentifier{
			Context: node.Parent().String(),
			Package: packageName,
			Type:    typeName})

	// Channel receives can be sources
	case *ssa.UnOp:
		if node.Op == token.ARROW {
			packageName, typeName, err := lang.FindEltTypePackage(node.X.Type(), "%s")
			if err != nil {
				return false
			}
			return f(config.CodeIdentifier{
				Context: node.Parent().String(),
				Package: packageName,
				Type:    typeName,
				Kind:    "channel receive"})
		}
		return false

	default:
		return false
	}
}

// isInterfaceEntrypoint returns true if the interface method or any interface implementation matches an entrypoint.
func isInterfaceEntrypoint(params EntrypointParams, node *ssa.Call, parent *ssa.Function) bool {
	classifier := params.Classifier
	implsByType := params.InterfaceImpls
	f := params.CodeIDOracle
	receiver := node.Call.Value.Name()
	methodName := node.Call.Method.Name()
	calleePkg := lang.FindSafeCalleePkg(node.Common())
	if calleePkg.IsSome() {
		if classifier != nil && classifier.CanClassify(parent) {
			for name, impls := range implsByType {
				// node.Call.Method.FullName has the receiver in parentheses, so they must be removed
				calleeName := strings.ReplaceAll(node.Call.Method.FullName(), "(", "")
				calleeName = strings.ReplaceAll(calleeName, ")", "")
				if name == calleeName {
					for impl := range impls {
						if impl.Package() != nil {
							cpb := classifier.ClassifyFunc(impl, impl.Package().Pkg.Path()).String()
							callerPkg := lang.PackageNameFromFunction(parent)
							cid := config.CodeIdentifier{
								Package: calleePkg.Value(), Method: methodName, Receiver: receiver, Capability: cpb, Context: callerPkg,
							}
							if f(cid) {
								return true
							}
						}
					}
				}
			}
		}
		cid := config.CodeIdentifier{
			Context:  parent.String(),
			Package:  calleePkg.Value(),
			Method:   methodName,
			Receiver: receiver,
		}
		return f(cid)
	}
	return false
}

// isFuncEntrypoint returns true if the actual function called matches an entrypoint.
func isFuncEntrypoint(params EntrypointParams, node *ssa.Call, parent *ssa.Function) bool {
	classifier := params.Classifier
	f := params.CodeIDOracle
	funcValue := node.Call.Value.Name()
	calleePkg := lang.FindSafeCalleePkg(node.Common())
	if calleePkg.IsSome() {
		cpb := ""
		context := parent.String()
		if classifier != nil && classifier.CanClassify(parent) {
			if callee, ok := node.Call.Value.(*ssa.Function); ok {
				cpb = classifier.ClassifyFunc(callee, calleePkg.Value()).String()
				callerPkg := lang.PackageNameFromFunction(parent)
				context = callerPkg
			}
		}
		cid := config.CodeIdentifier{
			Context:    context,
			Package:    calleePkg.Value(),
			Method:     funcValue,
			Capability: cpb,
		}
		return f(cid)
	}
	return false
}

// isAliasEntrypoint returns true if any alias to node matches an entrypoint.
func isAliasEntrypoint(params EntrypointParams, node *ssa.Call, parent *ssa.Function) bool {
	p := params.Pointer
	classifier := params.Classifier
	f := params.CodeIDOracle
	if p == nil {
		return false
	}
	ptr, hasAliases := p.Queries[node.Call.Value]
	if !hasAliases {
		return false
	}
	for _, label := range ptr.PointsTo().Labels() {
		funcValue := label.Value().Name()
		funcPackage := lang.FindValuePackage(label.Value())
		if funcPackage.IsSome() {
			cpb := ""
			context := parent.String()
			if classifier != nil && classifier.CanClassify(parent) {
				if callee, ok := node.Call.Value.(*ssa.Function); ok {
					cpb = classifier.ClassifyFunc(callee, funcPackage.Value()).String()
					callerPkg := lang.PackageNameFromFunction(parent)
					context = callerPkg
				}
			}
			cid := config.CodeIdentifier{
				Context:    context,
				Package:    funcPackage.Value(),
				Method:     funcValue,
				Capability: cpb,
			}
			if f(cid) {
				fmt.Printf("alias entry: %+v\n", cid)
				return true
			}
		}
	}
	return false
}
