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
	"math/rand/v2"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/rewrite"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type reflectValueSpec struct {
	classLike lang.NamedTypeModuloPointer
	lhs       *ast.Ident
	value     *ast.Ident
	arg       *ast.Ident
}

// ReflectValueCallRewriterSpec specifies the code elements the reflect value call rewriter should look for when rewriting.
type ReflectValueCallRewriterSpec struct {
	// The code identifier used to identify the consumer of the class-like type.
	Cid config.CodeIdentifier
	// The class-like type
	ReceiverType lang.NamedTypeModuloPointer
	// The location where the consumer was found (a call instruction)
	Location ssa.Instruction
}

// Compile a ReflectValueCallRewriterSpec to a RVCRewriterResolvedSpec resolves the paths
// necessary to move the code of the reflect calling package.
func (r ReflectValueCallRewriterSpec) Compile(lps *loadprogram.State) RVCRewriterResolvedSpec {
	parentTypePackage := r.Location.Parent().Pkg.Pkg
	parentPkgDir := analysisutil.PackageDir(r.Location.Parent().Pkg.Prog.Fset, parentTypePackage)
	calleePkg := "generated_pkg"
	calleePkgPath := ""
	calleePkgDir := ""
	if callInstr, ok := r.Location.(ssa.CallInstruction); ok {
		if calleeFunc, ok := callInstr.Common().Value.(*ssa.Function); ok {
			calleePkgDir = analysisutil.PackageDir(calleeFunc.Prog.Fset, calleeFunc.Pkg.Pkg) + "/"
			calleePkg = calleeFunc.Pkg.Pkg.Name()
			calleePkgPath = calleeFunc.Pkg.Pkg.Path()
		}
	}

	// If it's the same package, no need to remap files.
	if calleePkgDir == parentPkgDir+"/" {
		return RVCRewriterResolvedSpec{
			Cid:                     r.Cid,
			ReceiverType:            r.ReceiverType,
			ParentPkg:               parentTypePackage,
			OldReflecterPackagePath: calleePkgPath,
			OldReflecterPackageDir:  calleePkgDir,
			NewPkgName:              calleePkg,
			NewReflecterPackagePath: calleePkgPath,
			NewReflecterPackageDir:  calleePkgDir,
		}
	}

	suffix := calleePkg + strconv.Itoa(rand.IntN(10e4)) + "generated"
	var prefix string
	if parentTypePackage.Path() == "command-line-arguments" {
		additional := strings.TrimPrefix(parentPkgDir, lps.GoModInfo.Dir)
		prefix = lps.GoModInfo.Path + additional
	} else {
		prefix = parentTypePackage.Path()
	}
	// amazonq-ignore-next-line
	newPkg := path.Join(prefix, suffix)
	newPkgDir := filepath.Join(parentPkgDir, suffix)

	return RVCRewriterResolvedSpec{
		Cid:                     r.Cid,
		ReceiverType:            r.ReceiverType,
		ParentPkg:               parentTypePackage,
		OldReflecterPackagePath: calleePkgPath,
		OldReflecterPackageDir:  calleePkgDir,
		NewPkgName:              suffix,
		NewReflecterPackagePath: newPkg,
		NewReflecterPackageDir:  newPkgDir,
	}
}

// RVCRewriterResolvedSpec is similar to the ReflectValueCallRewriterSpec but some identifiers have been
// resolved.
type RVCRewriterResolvedSpec struct {
	// The code identifier used to identify the consumer of the class-like type.
	Cid config.CodeIdentifier
	// The class-like type
	ReceiverType lang.NamedTypeModuloPointer
	ParentPkg    *types.Package
	// The new package name
	NewPkgName string
	// The new package path: where to move the go imports
	NewReflecterPackagePath string
	// The new package directory: where to move the go files
	NewReflecterPackageDir string
	// The old package path: where to move the go imports
	OldReflecterPackagePath string
	// The old package dir: where to take the files from
	OldReflecterPackageDir string
}

// remapFilePath remaps a file path if necessary.
func (r RVCRewriterResolvedSpec) remapFilePath(path string) string {
	dir, file := filepath.Split(path)
	// It is only necessary to remap files that are exactly in the package using reflection.
	// The remapped files can still use the public methods from the other packages
	// TODO: not true for internal packages - need to check for it, and reject / support internal by copying
	if dir != r.OldReflecterPackageDir {
		return path
	}
	return filepath.Join(r.NewReflecterPackageDir, file)
}

// remapPackagePath remaps a package path.
func (r RVCRewriterResolvedSpec) remapPackagePath(importPath string) (string, bool) {
	if after, found := strings.CutPrefix(formatutil.Unquote(importPath)+"/", r.OldReflecterPackagePath+"/"); found {
		return fmt.Sprintf("%q", r.NewReflecterPackagePath+after), true
	}
	return "", false
}

// remapPackageName returns the new package name and true when the package name of the given
// file path needs to be changed.
func (r RVCRewriterResolvedSpec) remapPackageName(path string) (string, bool) {
	dir, _ := filepath.Split(path)
	// It is only necessary to remap files that are exactly in the package using reflection.
	// The remapped files can still use the public methods from the other packages
	// TODO: not true for internal packages - need to check for it, and reject / support internal by copying
	if dir != r.OldReflecterPackageDir {
		return "", false
	}
	return r.NewPkgName, true
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
	rspec RVCRewriterResolvedSpec,
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
			astBuilder := lang.NewAstBuildManager(p, file)
			for _, node := range file.Decls {
				astutil.Apply(node,
					func(c *astutil.Cursor) bool { return nodeTransform(c, pts, rspec, astBuilder) }, nil)
			}
			originalFileName := pts.Program.Fset.File(file.FileStart).Name()
			// if the file has changed, write the file and add it to the overlay
			if astBuilder.FileChanged {
				// Remove all comments to avoid problems
				file.Comments = []*ast.CommentGroup{}
				astBuilder.RegisterImports()
			}
			// Remap imports that have rspec old package prefix to new package prefix
			for _, imp := range file.Imports {
				if newImportPath, mapped := rspec.remapPackagePath(imp.Path.Value); mapped {
					pts.Logger.Infof("In    %s\n"+
						"      remap %s\n"+
						"       to   %s", originalFileName, imp.Path.Value, newImportPath)
					// Use the old name when importing
					if imp.Name == nil {
						imp.Name = ast.NewIdent(lang.ExtractPkgNameFromPath(formatutil.Unquote(imp.Path.Value)))
					}
					imp.Path.Value = newImportPath
					astBuilder.FileChanged = true
				}
			}

			// The package name needs updating if this is supposed to be part of the new package
			if newPkgName, mapped := rspec.remapPackageName(originalFileName); mapped {
				pts.Logger.Infof("Remap package name %s to %s", p.Name, newPkgName)
				setPkgName(file, newPkgName)
				astBuilder.FileChanged = true
			}

			if astBuilder.FileChanged {
				filePath := rspec.remapFilePath(originalFileName)
				contents, err := rewrite.AstFileToBytes(pts.Program.Fset, file)
				if err != nil {
					panic(err)
				}
				newOverlayElements[filePath] = contents
			}
		}
	})

	return newOverlayElements
}

func nodeTransform(
	c *astutil.Cursor,
	pts *loadprogram.State,
	rspec RVCRewriterResolvedSpec,
	astBuilder *lang.AstBuildManager) bool {
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

	if vc, ok := isReflectValueCall(*astBuilder.Package, c.Node()); ok {
		vc.classLike = rspec.ReceiverType
		// Not necessary for the rewrite: simulate the interface
		_, interfaceSpec := astBuilder.MakeInterfaceForClass(pts.Program, astBuilder.Package.Types, vc.classLike)
		strb := strings.Builder{}
		printer.Fprint(&strb, pts.Program.Fset, interfaceSpec)
		pts.Logger.Debugf("Interface would be: interface %s\n", strb.String())
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

func isReflectValueCall(p packages.Package, node ast.Node) (reflectValueSpec, bool) {
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
	// reflectValueIdent must have the right type, i.e. it's a reflect.Value
	rt := p.TypesInfo.TypeOf(reflectValueIdent)
	if rt == nil || rt.String() != "reflect.Value" {
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
	// The statements are listed in the reverse order they should appear. The proper order is:
	// - assign the receiver struct for the method call,
	// - switch statement over all possible methods this receiver can call.
	// The statements will be inserted in the reverse order in the ast by the caller, so we put
	// the switch statement first
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
		body = append(body, assignmt)
		args = append(args, arg)
	}

	// Declare concrete and reflect return values
	results := methodType.Results()
	resVars := []*types.Var{}
	reflectVars := []*types.Var{}
	for i := 0; i < results.Len(); i++ {
		rt := results.At(i)
		rtyp := rt.Type()
		rtypName := rewrite.TypeNameForGeneration(rtyp)
		rx := rewrite.FreshVar(builder.Package.Types, scope,
			genName(methodName, rtypName), rt.Type())
		resVars = append(resVars, rx)
		rxRefl := newReflectValueVar(builder, scope, rx)
		reflectVars = append(reflectVars, rxRefl)
		body = append(body, builder.NewVarDecl(rx))
		// Declare the reflect.Value variable for the actual result variable
		body = append(body, &ast.DeclStmt{
			Decl: &ast.GenDecl{
				Tok: token.VAR,
				Specs: []ast.Spec{
					&ast.ValueSpec{
						Names: []*ast.Ident{ast.NewIdent(rxRefl.Name())},
						Type: &ast.SelectorExpr{
							X:   ast.NewIdent("reflect"),
							Sel: ast.NewIdent("Value"),
						},
					},
				},
			},
		})
		// If the type of the result is an interface, initialize the reflect.Value
		// variable to the zero value.
		// See the comment below for more details on why this is necessary.
		if types.IsInterface(rtyp) {
			body = append(body,
				lang.NewMultiAssignDecl([]string{rxRefl.Name()}, newReflectZeroVal(builder, rtyp)))
		}
	}

	// Get the method results
	methodResults := methodType.Results()
	if methodResults.Len() == 0 {
		// No result; just call the method
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
		body = append(body, lang.NewMultiAssignDecl(
			funcutil.Map(resVars, func(v *types.Var) string { return v.Name() }),
			fcall))
		// Assign results
		for i := 0; i < results.Len(); i++ {
			reflectValVarName := reflectVars[i].Name()
			reflectValueCall := &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "reflect"},
					Sel: &ast.Ident{Name: "ValueOf"},
				},
				Args: []ast.Expr{
					&ast.Ident{Name: resVars[i].Name()},
				},
			}
			// If the type is an interface, only call reflect.ValueOf if it's non-nil.
			// Otherwise, it remains as the zero value of the interface.
			// This is important because reflect.ValueOf does not construct a
			// typed nil value when passed a nil interface value.
			if types.IsInterface(resVars[i].Type()) {
				body = append(body, &ast.IfStmt{
					Cond: &ast.BinaryExpr{
						X:  &ast.Ident{Name: resVars[i].Name()},
						Op: token.NEQ,
						Y:  &ast.Ident{Name: "nil"},
					},
					Body: &ast.BlockStmt{
						List: []ast.Stmt{
							lang.NewMultiAssignDecl([]string{reflectValVarName}, reflectValueCall),
						},
					},
				})
			} else {
				body = append(body, lang.NewMultiAssignDecl(
					[]string{reflectValVarName}, reflectValueCall))
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
							&ast.Ident{Name: reflectValVarName},
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

const reflectValNameSuffix = "ReflectVal"

// newReflectValueVar creates a new variable name to store the reflect.Value value of ref.
func newReflectValueVar(builder *lang.AstBuildManager, scope *types.Scope, ref *types.Var) *types.Var {
	return rewrite.FreshVar(
		builder.Package.Types, scope, ref.Name()+reflectValNameSuffix,
		ref.Type()) // this type doesn't have to be reflect.Value since it's just used to generate a new name
}

// newReflectZeroVal constructs the reflect.Zero value of type t.
// It uses a typed nil pointer to the interface type because otherwise the
// interface value to reflect.TypeOf is converted to interface{} and loses its
// concrete type.
// Source: https://stackoverflow.com/a/68866751
//
// E.g., if t is iface then this function returns:
//
//	reflect.Zero(reflect.TypeOf((*iface)(nil)).Elem())
func newReflectZeroVal(builder *lang.AstBuildManager, t types.Type) *ast.CallExpr {
	return &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   &ast.Ident{Name: "reflect"},
			Sel: &ast.Ident{Name: "Zero"},
		},
		Args: []ast.Expr{
			&ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X: &ast.CallExpr{
						Fun: &ast.SelectorExpr{
							X:   &ast.Ident{Name: "reflect"},
							Sel: &ast.Ident{Name: "TypeOf"},
						},
						Args: []ast.Expr{
							&ast.CallExpr{
								Fun: &ast.ParenExpr{
									X: &ast.StarExpr{
										X: builder.NewAstTypeExpr(t),
									},
								},
								Args: []ast.Expr{
									&ast.Ident{Name: "nil"},
								},
							},
						},
					},
					Sel: &ast.Ident{Name: "Elem"},
				},
				Args: []ast.Expr{}, // call to (reflect.Type).Elem takes no arguments
			},
		},
	}
}

func genName(methodName, typeName string) string {
	typeSuffix := strings.TrimPrefix(typeName, methodName)
	return formatutil.LowerFirst(methodName) + formatutil.UpperFirst(typeSuffix) + "V"
}

func setPkgName(f *ast.File, packageName string) {
	// The package name is the Name field in the file
	f.Name = &ast.Ident{Name: packageName}
}
