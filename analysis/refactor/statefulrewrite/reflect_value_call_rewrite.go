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
	"go/printer"
	"go/token"
	"go/types"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/rewrite"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type reflectValueSpec struct {
	classLike lang.MaybeRefNamedType
	lhs       *ast.Ident
	value     *ast.Ident
	arg       *ast.Ident
}

// ReflectValueCallRewriterSpec specifies the code elements the reflect value call rewriter should look for when rewriting.
type ReflectValueCallRewriterSpec struct {
	Cid          config.CodeIdentifier
	ReceiverType lang.MaybeRefNamedType
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
func RewriteCallsToReflectValueCall(
	pts *loadprogram.State,
	rspec ReflectValueCallRewriterSpec,
) map[string][]byte {
	newOverlayElements := map[string][]byte{}
	rewrite.ForEachPackageIncludingDependencies(pts.Packages, func(p *packages.Package) {
		// Find the methodset of implt
		if p.Types == nil {
			return
		}
		if rspec.ReceiverType.Named == nil {
			return
		}

		for _, file := range p.Syntax {
			// =====
			astBuilder := lang.NewAstBuildManager(p, file)
			for _, node := range file.Decls {

				astutil.Apply(node, func(c *astutil.Cursor) bool { return nodeTransform(c, pts, rspec, astBuilder) }, nil)
			}

			// if the file has changed, write the file and add it to the overlay
			if astBuilder.FileChanged {
				// Remove all comments to avoid problems
				file.Comments = []*ast.CommentGroup{}
				astBuilder.RegisterImports()
				contents, err := rewrite.AstFileToBytes(pts.Program.Fset, file)
				if err != nil {
					panic(err)
				}
				newOverlayElements[pts.Program.Fset.File(file.FileStart).Name()] = contents
			}
		}
	})

	return newOverlayElements
}

func nodeTransform(
	c *astutil.Cursor,
	pts *loadprogram.State,
	rspec ReflectValueCallRewriterSpec,
	astBuilder *lang.AstBuildManager) bool {
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

	if vc, ok := isReflectValueCall(c.Node()); ok {
		vc.classLike = rspec.ReceiverType
		// Not necessary for the rewrite: simulate the interface
		_, interfaceSpec := astBuilder.MakeInterfaceForClass(pts.Program, astBuilder.Package.Types, vc.classLike)
		strb := strings.Builder{}
		printer.Fprint(&strb, pts.Program.Fset, interfaceSpec)
		pts.Logger.Infof("Interface would be: interface %s\n", strb.String())
		// Now rewrite
		for _, stmt := range constructPreface(astBuilder, vc) {
			c.InsertBefore(stmt)
		}
		for _, stmt := range constructReflectValueCallReplacements(pts.Program, astBuilder, vc) {
			c.InsertAfter(stmt)
		}
		c.Delete()
		pts.Logger.Infof("Rewrote reflect.Value.Call() to direct method call in %s\n",
			pts.Program.Fset.File(astBuilder.File.FileStart).Name())
		astBuilder.FileChanged = true
	}
	return true
}

func isReflectValueCall(node ast.Node) (reflectValueSpec, bool) {
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

func constructPreface(astBuilder *lang.AstBuildManager, spec reflectValueSpec) []ast.Stmt {
	// need to reintroduce the lhs decl so that it is defined for later usages
	lhsType := astBuilder.Package.TypesInfo.TypeOf(spec.lhs)
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

func constructReflectValueCallReplacements(
	program *ssa.Program,
	builder *lang.AstBuildManager,
	spec reflectValueSpec,
) []ast.Stmt {
	methods := program.MethodSets.MethodSet(spec.classLike.Actual)
	clauses := []ast.Stmt{}
	// Instantiate a receiver with a fresh name
	scope := builder.Package.Types.Scope().Innermost(spec.value.Pos())
	receiverVar := rewrite.FreshVar(builder.Package.Types, scope, spec.value.Name+"Instance", spec.classLike.Named)
	ccs := caseClauseSpec{
		lhs:      spec.lhs.Name,
		receiver: receiverVar,
		argument: spec.arg.Name,
	}

	for i := 0; i < methods.Len(); i++ {
		method := methods.At(i)
		clauses = append(clauses, constructSwitchCase(builder, scope, method, ccs))
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
		genReceiverAssignStmt(builder, receiverVar.Name(), spec),
	}
}

func genReceiverAssignStmt(builder *lang.AstBuildManager, receiverName string, spec reflectValueSpec) ast.Stmt {
	structLit := &ast.CompositeLit{
		Type: builder.NewAstTypeExpr(spec.classLike.Named),
		Elts: nil, // empty struct initialization
	}
	var rhs ast.Expr
	// If the receiver is a pointer, we need to take the address of the struct
	if spec.classLike.IsRef {
		rhs = &ast.UnaryExpr{
			Op: token.AND,
			X:  structLit,
		}
	} else {
		rhs = structLit
	}
	return &ast.AssignStmt{
		Lhs: []ast.Expr{
			&ast.Ident{Name: receiverName},
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{rhs},
	}
}

type caseClauseSpec struct {
	lhs      string
	receiver *types.Var
	argument string
}

func constructSwitchCase(
	builder *lang.AstBuildManager,
	scope *types.Scope,
	method *types.Selection,
	cs caseClauseSpec,
) *ast.CaseClause {
	// Get the method type
	methodType := method.Type().(*types.Signature)
	// Get the method parameters
	methodParams := methodType.Params()
	methodName := method.Obj().Name()

	args := []ast.Expr{}
	var body []ast.Stmt
	for i := 0; i < methodParams.Len(); i++ {
		param := methodParams.At(i)
		reflectVal := ast.IndexExpr{
			X:     &ast.Ident{Name: cs.argument},
			Index: &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", i)},
		}
		argVar := rewrite.FreshVar(builder.Package.Types, scope, param.Name(), param.Type())
		// Generate the assignment argName := reflectVal.Interface().(param.Type())
		assignmt := lang.NewSingleAssignDecl(argVar.Name(), &ast.TypeAssertExpr{
			X: &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &reflectVal,
					Sel: &ast.Ident{Name: "Interface"},
				},
				Args: []ast.Expr{},
			},
			Type: builder.NewAstTypeExpr(param.Type()),
		})
		arg := &ast.Ident{Name: argVar.Name()}
		//
		body = append(body, assignmt)
		args = append(args, arg)
	}

	// Declare return values
	results := methodType.Results()
	resNames := []string{}
	for i := 0; i < results.Len(); i++ {
		rt := results.At(i)
		rtypName := rewrite.TypeNameForGeneration(rt.Type())
		rx := rewrite.FreshVar(builder.Package.Types, scope, genName(methodName, rtypName), rt.Type())

		resNames = append(resNames, rx.Name())
		body = append(body, builder.NewVarDecl(rx))
	}

	// Get the method results
	methodResults := methodType.Results()
	if methodResults.Len() == 0 {
		// No result; jsut call the method
		body = append(body,
			&ast.ExprStmt{
				X: &ast.CallExpr{
					Fun: &ast.SelectorExpr{
						X: &ast.Ident{Name: cs.receiver.Name()},
						Sel: &ast.Ident{
							Name: method.Obj().Name(),
						},
					},
					Args: args,
				},
			},
		)
	} else {
		// There are results, the return values have been declared. Assign a value and
		// convert back to reflect value.
		fcall := &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X: &ast.Ident{Name: cs.receiver.Name()},
				Sel: &ast.Ident{
					Name: method.Obj().Name(),
				},
			},
			Args: args,
		}
		body = append(body, lang.NewMultiAssignDecl(resNames, fcall))
		// Assign results
		for i := 0; i < results.Len(); i++ {
			reflectValueCall := &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "reflect"},
					Sel: &ast.Ident{Name: "ValueOf"},
				},
				Args: []ast.Expr{
					&ast.Ident{Name: resNames[i]},
				},
			}
			body = append(body, &ast.AssignStmt{
				Lhs: []ast.Expr{
					&ast.Ident{Name: cs.lhs},
				},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{
					&ast.CallExpr{
						Fun: &ast.Ident{Name: "append"},
						Args: []ast.Expr{
							&ast.Ident{Name: cs.lhs},
							reflectValueCall,
						},
					},
				},
			})
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

func genName(methodName, typeName string) string {
	typeSuffix := strings.TrimPrefix(typeName, methodName)
	return formatutil.LowerFirst(methodName) + formatutil.UpperFirst(typeSuffix) + "V"
}
