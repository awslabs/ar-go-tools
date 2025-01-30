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

package statefulrewrite

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

// StatefulRewritesOverlayTransform transforms the overlay in the config state by building
// the program, computing the necessary stateful rewrites, and setting the overlay in the
// config state with the appropriate rewritten files.
func StatefulRewritesOverlayTransform(c *config.State) result.Result[config.State] {
	newOverlayElements := map[string][]byte{}

	// Build a pointer state
	state, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
	RewriteCallsToReflectValueCall(state.Packages)
	if err != nil {
		return result.Err[config.State](err)
	}

	for k, v := range newOverlayElements {
		c.Overlay[k] = v
	}

	return result.Ok(c)
}

func RewriteCallsToReflectValueCall(pkgs []*packages.Package) {
	forEachPackageIncludingDependencies(pkgs, func(p *packages.Package) {
		for _, file := range p.Syntax {
			for _, node := range file.Decls {
				pre := func(c *astutil.Cursor) bool {
					// If the current node, c.Node(), is a call to sort.Sort (or
					// sort.Stable or sort.IsSorted), replace it with calls to
					// obj.Less, obj.Swap, and obj.Len, where obj is the argument
					// that was passed to sort.
					if _, ok := c.Node().(ast.Stmt); !ok {
						// c.Node() is not a statement.
						return true
					}
					canRewrite := false
					switch c.Parent().(type) {
					case *ast.BlockStmt, *ast.CaseClause, *ast.LabeledStmt:
						canRewrite = true
					case *ast.CommClause:
						canRewrite = c.Index() >= 0
					}
					if !canRewrite {
						// The statement is in a position in the syntax tree where it
						// can't be replaced with a block or with multiple statements, so
						// we give up.
						return true
					}

					if isReflectValueCall(p.TypesInfo, c.Node()) {
						c.Replace(&ast.BlockStmt{List: []ast.Stmt{}})
					}
					return true
				}
				astutil.Apply(node, pre, nil)
			}
		}
	})
}

func isReflectValueCall(info *types.Info, node ast.Node) bool {
	expr, ok := node.(*ast.AssignStmt)
	if !ok {
		// Not a statement node.
		return false
	}
	call, ok := expr.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if callee.Sel.Name != "Call" {
		fmt.Println("call Call")
		// The method is not "Value".
		return false
	}
	pkgIdent, ok := callee.X.(*ast.Ident)
	if !ok {
		// The left-hand-side of the selection is not a plain identifier.
		return false
	}
	pkgName, ok := info.Uses[pkgIdent].(*types.PkgName)
	if !ok {
		// The identifier does not refer to a package.
		return false
	}
	if strings.Contains(pkgName.Name(), "reflect") {
		fmt.Println(pkgName.Name())
		// The package is "reflect".
		return false
	}
	return true
}

// forEachPackageIncludingDependencies calls fn exactly once for each package
// that is in pkgs or in the transitive dependencies of pkgs.
func forEachPackageIncludingDependencies(pkgs []*packages.Package, fn func(*packages.Package)) {
	visitedPackages := make(map[*packages.Package]struct{})
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if _, ok := visitedPackages[p]; ok {
			return
		}
		visitedPackages[p] = struct{}{}
		for _, p2 := range p.Imports {
			visit(p2)
		}
		fn(p)
	}
	for _, p := range pkgs {
		visit(p)
	}
}
