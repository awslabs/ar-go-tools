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

package refactor

import (
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/dave/dst"
	"github.com/dave/dst/decorator"
	"github.com/dave/dst/dstutil"
)

type transform func(*lang.FuncInfo, *dstutil.Cursor) bool

// buildScopeTree collects information about the AST and links children nodes to parent nodes in the funcInfo.NodeMap
func buildScopeTree(funcInfo *lang.FuncInfo, c *dstutil.Cursor) bool {
	n := c.Node()
	p := c.Parent()
	if n != nil && p != nil {
		if parent, ok := funcInfo.NodeMap[p]; ok {
			cur := &lang.NodeTree{Parent: parent, Label: n}
			funcInfo.NodeMap[n] = cur
		}
	}
	return true
}

// WithScope applies the transform post to packages as a post operation in Apply. It first runs the function
// that builds information necessary to have access to closest scopes within a function.
// The post transform can use the FuncInfo's various scope operations
func WithScope(packages []*decorator.Package, post transform) {
	for _, pack := range packages {
		for _, dstFile := range pack.Syntax {
			// Create a new decorator, which will track the mapping between ast and dst nodes
			for _, decl := range dstFile.Decls {
				if funcDecl, ok := decl.(*dst.FuncDecl); ok {
					m := map[dst.Node]*lang.NodeTree{}
					root := &lang.NodeTree{Parent: nil, Label: funcDecl}
					m[funcDecl] = root
					fi := &lang.FuncInfo{
						Package:   pack,
						Decorator: pack.Decorator,
						File:      dstFile,
						NodeMap:   m,
						Decl:      funcDecl,
					}

					dstutil.Apply(funcDecl,
						// pre function applied in pre-order traversal
						func(c *dstutil.Cursor) bool {
							return buildScopeTree(fi, c)
						},
						// post function applied in post-order
						func(c *dstutil.Cursor) bool {
							return post(fi, c)
						})
				}
			}
		}
	}
}
