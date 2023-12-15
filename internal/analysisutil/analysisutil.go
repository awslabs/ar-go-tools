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
	"go/token"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// IsEntrypointNode returns true if n is an entrypoint to the analysis according to f.
func IsEntrypointNode(pointer *pointer.Result, n ssa.Node, f func(config.CodeIdentifier) bool) bool {
	switch node := (n).(type) {
	// Look for callees to functions that are considered entry points
	case *ssa.Call:
		if node == nil {
			return false // inits cannot be entry points
		}

		parent := node.Parent()
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg := lang.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return f(
					config.CodeIdentifier{
						Context:  parent.String(),
						Package:  calleePkg.Value(),
						Method:   methodName,
						Receiver: receiver})
			}
			return false
		}
		return isFuncEntrypoint(node, parent, f) || isAliasEntrypoint(pointer, node, f)

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

// isFuncEntrypoint returns true if the actual function called matches an entrypoint.
func isFuncEntrypoint(node *ssa.Call, parent *ssa.Function, f func(config.CodeIdentifier) bool) bool {
	funcValue := node.Call.Value.Name()
	calleePkg := lang.FindSafeCalleePkg(node.Common())
	if calleePkg.IsSome() {
		return f(config.CodeIdentifier{Context: parent.String(), Package: calleePkg.Value(), Method: funcValue})
	}
	return false
}

// isAliasEntrypoint returns true if any alias to node matches an entrypoint.
func isAliasEntrypoint(pointer *pointer.Result, node *ssa.Call, f func(config.CodeIdentifier) bool) bool {
	if pointer == nil {
		return false
	}
	ptr, hasAliases := pointer.Queries[node.Call.Value]
	if !hasAliases {
		return false
	}
	for _, label := range ptr.PointsTo().Labels() {
		funcValue := label.Value().Name()
		funcPackage := lang.FindValuePackage(label.Value())
		if funcPackage.IsSome() && f(config.CodeIdentifier{Package: funcPackage.Value(), Method: funcValue}) {
			return true
		}
	}
	return false
}
