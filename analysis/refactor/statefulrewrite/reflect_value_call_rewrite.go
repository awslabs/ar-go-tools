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
	"go/token"
	"go/types"

	"github.com/awslabs/ar-go-tools/internal/rewrite"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type reflectValueSpec struct {
	methoder types.Object
	lhs      *ast.Ident
	value    *ast.Ident
	arg      *ast.Ident
}

// RewriteCallsToReflectValueCall transforms reflect.Value.Call() invocations into direct method calls.
//
// It analyzes packages and their dependencies to find reflect.Value.Call() usage and rewrites them
// into equivalent direct method calls on concrete types. This helps avoid reflection overhead.
//
// The function:
// 1. Finds the "MethodGroup" type in each package
// 2. Gets its method set
// 3. For each reflect.Value.Call() found:
//   - Generates a switch statement to dispatch to the appropriate concrete method
//   - Preserves variable declarations and assignments
//   - Maintains program semantics while removing reflection
//
// Parameters:
//   - program: The SSA-form program to analyze
//   - pkgs: The packages to process
//
// Returns:
//   - A map from filename to rewritten file contents as bytes
//   - Only files that were modified are included in the map
func RewriteCallsToReflectValueCall(program *ssa.Program, pkgs []*packages.Package) map[string][]byte {
	newOverlayElements := map[string][]byte{}
	rewrite.ForEachPackageIncludingDependencies(pkgs, func(p *packages.Package) {
		// Find the methodset of implt
		if p.Types == nil {
			return
		}
		// Find the "MethodGroup" type
		obj := p.Types.Scope().Lookup("MethodGroup")
		if obj != nil {
			fmt.Printf("Found %s = %v\n", obj.Name(), obj)
		} else {
			return
		}
		methodSet := program.MethodSets.MethodSet(obj.Type())

		for _, file := range p.Syntax {
			fileHasChanged := false
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

					if vc, ok := isReflectValueCall(p.TypesInfo, c.Node()); ok {
						vc.methoder = obj
						for _, stmt := range constructPreface(p, vc) {
							c.InsertBefore(stmt)
						}
						for _, stmt := range constructReflectValueCallReplacements(p, vc, methodSet) {
							c.InsertAfter(stmt)
						}
						c.Delete()
						fileHasChanged = true
					}
					return true
				}
				astutil.Apply(node, pre, nil)
			}
			if fileHasChanged {
				contents, err := rewrite.AstFileToBytes(program.Fset, file)
				if err != nil {
					panic(err)
				}
				newOverlayElements[program.Fset.File(file.FileStart).Name()] = contents
			}
		}
	})

	return newOverlayElements
}

func isReflectValueCall(info *types.Info, node ast.Node) (reflectValueSpec, bool) {
	// Test expr is of the form  [_ := _]
	expr, ok := node.(*ast.AssignStmt)
	if !ok {
		// Not a statement node.
		return reflectValueSpec{}, false
	}
	// Test lhs is of the form [_]
	if len(expr.Lhs) != 1 {
		return reflectValueSpec{}, false
	}
	// Test lhs is of the form [_ := _]
	lhsIdent, ok := expr.Lhs[0].(*ast.Ident)
	if !ok {
		return reflectValueSpec{}, false
	}

	// Test rhs is of the form [_ := <rhs>]
	if len(expr.Rhs) != 1 {
		return reflectValueSpec{}, false
	}
	// Expr is of the form [_ := <call>(_)]
	call, ok := expr.Rhs[0].(*ast.CallExpr)
	if !ok {
		return reflectValueSpec{}, false
	}
	// Expr is of the form [_ := <callee.X>.<callee.Sel>(_)]
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return reflectValueSpec{}, false
	}
	// Expr is of the form [_ := <callee.X>.Call(_)]
	if callee.Sel.Name != "Call" {
		// The method is not "Call".
		return reflectValueSpec{}, false
	}
	// Expr is of the form [_ := reflectValueIdent.Call(_)]
	reflectValueIdent, ok := callee.X.(*ast.Ident)
	if !ok {
		// The left-hand-side of the selection is not a plain identifier.
		return reflectValueSpec{}, false
	}
	// Expr is of the form [_ := reflectValueIdent.Call(<arg>)]
	// where <arg> is a single identifier.
	if len(call.Args) != 1 {
		return reflectValueSpec{}, false
	}
	arg, ok := call.Args[0].(*ast.Ident)
	if !ok {
		return reflectValueSpec{}, false
	}
	return reflectValueSpec{
		lhs:   lhsIdent,
		value: reflectValueIdent,
		arg:   arg,
	}, true
}

func constructPreface(p *packages.Package, spec reflectValueSpec) []ast.Stmt {
	// need to reintroduce the lhs decl so that it is defined for later usages
	lhsType := p.TypesInfo.TypeOf(spec.lhs)
	lhsDecl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names: []*ast.Ident{{Name: spec.lhs.Name}},
					Type:  &ast.Ident{Name: lhsType.String()},
				},
			},
		},
	}
	// need to use the reflect value, otherwise it won't be used
	dummyValueUsage := &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.Ident{Name: "_"}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{spec.value},
	}
	return []ast.Stmt{dummyValueUsage, lhsDecl}
}

func constructReflectValueCallReplacements(p *packages.Package, spec reflectValueSpec, methods *types.MethodSet) []ast.Stmt {
	clauses := []ast.Stmt{}
	// Instantiate a receiver with a fresh name
	receiverName := rewrite.Fresh(p.Types.Scope().Innermost(spec.value.Pos()), spec.value.Name+"_instance")
	ccs := caseClauseSpec{
		lhs:      spec.lhs.Name,
		receiver: receiverName,
		argument: spec.arg.Name,
	}

	for i := 0; i < methods.Len(); i++ {
		method := methods.At(i)
		clauses = append(clauses, caseClause(method, ccs))
	}
	// Generate a switch statement
	switchStmt := &ast.SwitchStmt{
		Tag: &ast.Ident{Name: "opName"},
		Body: &ast.BlockStmt{
			List: clauses,
		},
	}
	// reverse order of statements
	return []ast.Stmt{
		switchStmt,
		genReceiverAssignStmt(receiverName, spec),
	}
}

func genReceiverAssignStmt(receiverName string, spec reflectValueSpec) ast.Stmt {
	return &ast.AssignStmt{
		Lhs: []ast.Expr{
			&ast.Ident{Name: receiverName},
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{
			&ast.CompositeLit{
				Type: &ast.Ident{Name: spec.methoder.Name()},
				Elts: nil, // empty struct initialization
			},
		},
	}
}

type caseClauseSpec struct {
	lhs      string
	receiver string
	argument string
}

func caseClause(method *types.Selection, cs caseClauseSpec) *ast.CaseClause {
	// Get the method type
	methodType := method.Type().(*types.Signature)
	// Get the method parameters
	methodParams := methodType.Params()
	args := []ast.Expr{}
	for i := 0; i < methodParams.Len(); i++ {
		args = append(args,
			&ast.IndexExpr{
				X:     &ast.Ident{Name: cs.argument},
				Index: &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", i)},
			},
		)
	}
	var body []ast.Stmt
	// Get the method results
	methodResults := methodType.Results()
	if methodResults.Len() == 0 {
		body = []ast.Stmt{
			&ast.ExprStmt{
				X: &ast.CallExpr{
					Fun: &ast.SelectorExpr{
						X: &ast.Ident{Name: cs.receiver},
						Sel: &ast.Ident{
							Name: method.Obj().Name(),
						},
					},
					Args: args,
				},
			},
		}
	} else {
		body = []ast.Stmt{
			&ast.AssignStmt{
				Lhs: []ast.Expr{
					&ast.Ident{Name: cs.lhs},
				},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{
					&ast.CallExpr{
						Fun: &ast.SelectorExpr{
							X: &ast.Ident{Name: cs.receiver},
							Sel: &ast.Ident{
								Name: method.Obj().Name(),
							},
						},
						Args: args,
					},
				},
			},
		}
	}

	// Create a new case clause
	return &ast.CaseClause{
		List: []ast.Expr{
			&ast.BasicLit{
				Kind:  token.STRING,
				Value: fmt.Sprintf("\"%s\"", method.Obj().Name()),
			},
		},
		Body: body,
	}
}
