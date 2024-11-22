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
	"github.com/awslabs/ar-go-tools/analysis/annotations"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// ResolveSsaNode tests whether a pair of annotation kind and tag apply to a specific ssa node.
// The tag "_" matches anything.
func (s *State) ResolveSsaNode(kind annotations.AnnotationKind, tag string, node ssa.Node) bool {
	switch n := node.(type) {
	case *ssa.Call:
		if n != nil {
			callees, err := s.ResolveCallee(n, false)
			if err != nil {
				return false
			}
			for callee := range callees {
				if fa, isAnnotated := s.Annotations.Funcs[callee]; isAnnotated {
					if funcutil.Exists(fa.Mains(), func(a annotations.Annotation) bool {
						return a.IsMatchingAnnotation(kind, tag)
					}) {
						return true
					}
				}
			}
		}
	}
	return false
}

// ResolveGraphNode tests whether a pair of annotation kind and tag apply to a specific dataflow graph node.
// The tag "_" matches anything.
func (s *State) ResolveGraphNode(kind annotations.AnnotationKind, tag string, node GraphNode) bool {
	switch n := node.(type) {
	case *CallNode:
		// CallNodes can only be sources
		if n.Callee() != nil && kind == annotations.Source {
			if fa, isAnnotated := s.Annotations.Funcs[n.Callee()]; isAnnotated {
				if funcutil.Exists(fa.Mains(), func(a annotations.Annotation) bool {
					return a.IsMatchingAnnotation(kind, tag)
				}) {
					return true
				}
			}
		}
	case *CallNodeArg:
		argCallee := n.ParentNode().Callee()
		if argCallee != nil && (kind == annotations.Sink || kind == annotations.Sanitizer) {
			if fa, isAnnotated := s.Annotations.Funcs[argCallee]; isAnnotated {
				if funcutil.Exists(fa.Mains(), func(a annotations.Annotation) bool {
					return a.IsMatchingAnnotation(kind, tag)
				}) {
					return true
				}
				// scanning with arguments: can track specific arguments as sinks/sanitized
				if n.argPos < len(argCallee.Params) {
					param := argCallee.Params[n.argPos]
					if paramAnnot, isAnnot := fa.Params()[param]; isAnnot {
						if funcutil.Exists(paramAnnot, func(a annotations.Annotation) bool {
							return a.IsMatchingAnnotation(kind, tag)
						}) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
