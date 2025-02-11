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

package lang

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/dave/dst"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// NewFalse returns a new AST structure that represents the boolean false
func NewFalse() *dst.BasicLit {
	return &dst.BasicLit{Value: "false"}
}

// NewInt returns a new AST structure that represents the integer value
func NewInt(value int) *dst.BasicLit {
	return &dst.BasicLit{Value: strconv.Itoa(value)}
}

// NewFloat64 returns a new AST structure that represents the float64 value
func NewFloat64(value float64) *dst.BasicLit {
	return &dst.BasicLit{Value: strconv.FormatFloat(value, 'E', -1, 64)}
}

// NewFloat32 returns a new AST structure that represents the float32 value
func NewFloat32(value float32) *dst.BasicLit {
	return &dst.BasicLit{Value: strconv.FormatFloat(float64(value), 'E', -1, 32)}
}

// NewString returns a new AST structure that represents the string value
func NewString(value string) *dst.BasicLit {
	return &dst.BasicLit{Value: "\"" + value + "\"", Kind: token.STRING}
}

// NewNil returns a dst expression that represents nil
func NewNil() dst.Expr {
	return dst.NewIdent("nil")
}

// NewPanic returns a new call expression that calls panic over the arguments args ...
func NewPanic(args ...dst.Expr) *dst.CallExpr {
	return &dst.CallExpr{
		Fun:      dst.NewIdent("panic"),
		Args:     args,
		Ellipsis: false,
	}
}

// NewDstTypeExpr returns an AST expression that represents the type t.
//
// For example, the expression that represents a types.Struct will be of the form
// struct{...}.
//
// For an integer, the expression is an identifier 'int'
func NewDstTypeExpr(t types.Type) (dst.Expr, error) {
	switch t0 := t.(type) {
	case *types.Basic:
		return dst.NewIdent(t0.String()), nil
	case *types.Named:
		// TODO: manage imports
		return dst.NewIdent(t0.String()), nil
	case *types.Struct:
		return newDstStructTypeExpr(t0)
	default:
		panic(fmt.Sprintf("implement NewTypeExpr for %s", t.String()))
	}
}

// newDstStructTypeExpr returns the expression representing a struct type, or an error if it could not create that
// expression.
func newDstStructTypeExpr(t *types.Struct) (dst.Expr, error) {
	n := t.NumFields()
	var fields []*dst.Field
	for i := 0; i < n; i++ {
		f := t.Field(i)
		te, err := NewDstTypeExpr(f.Type())
		if err != nil {
			return nil, err
		}
		newField := &dst.Field{
			Names: []*dst.Ident{dst.NewIdent(f.Name())},
			Type:  te,
			Tag:   nil,
		}
		fields = append(fields, newField)
	}
	res := &dst.StructType{
		Fields: &dst.FieldList{
			Opening: false,
			List:    fields,
			Closing: false,
			Decs:    dst.FieldListDecorations{},
		},
		Incomplete: false,
		Decs:       dst.StructTypeDecorations{},
	}
	return res, nil
}

// NewBinOp constructs a new binary expression
func NewBinOp(op token.Token, x, y dst.Expr) *dst.BinaryExpr {
	return &dst.BinaryExpr{
		X:    x,
		Op:   op,
		Y:    y,
		Decs: dst.BinaryExprDecorations{},
	}
}

// NewUnOp construct a new unary expression
func NewUnOp(op token.Token, x dst.Expr) *dst.UnaryExpr {
	return &dst.UnaryExpr{
		Op:   op,
		X:    x,
		Decs: dst.UnaryExprDecorations{},
	}
}

// AstBuildManager is a utility struct to help manage file rewriting. In particular it
// has functionality that makes managing imports easier.
type AstBuildManager struct {
	// fileChanged indicates whether the file has changed
	FileChanged bool
	// The package of the current file
	Package *packages.Package
	// The current file
	File *ast.File
	// The imports required by the generated code
	NewImports map[string]string
}

// NewAstBuildManager creates a new AstBuildManager
func NewAstBuildManager(pkg *packages.Package, file *ast.File) *AstBuildManager {
	return &AstBuildManager{
		Package:     pkg,
		File:        file,
		NewImports:  make(map[string]string),
		FileChanged: false,
	}
}

// RegisterImports adds the imports in NewImports to the file
func (a *AstBuildManager) RegisterImports() {
	// Append to file imports
	addedAny := false
	for importPath, importName := range a.NewImports {
		astutil.AddNamedImport(a.Package.Fset, a.File, importName, importPath)
	}
	a.FileChanged = a.FileChanged || addedAny
}

// NewAstTypeExpr returns an AST expression that represents the type t.
//
// For example, the expression that represents a types.Struct will be of the form
// struct{...}.
//
// For an integer, the expression is an identifier 'int'
//
// The function will panic for non-suppoted types. Currently, only base, pointer, named
// and struct types are supported.
func (a *AstBuildManager) NewAstTypeExpr(t types.Type) ast.Expr {
	switch t0 := t.(type) {
	case *types.Basic:
		return ast.NewIdent(t0.String())
	case *types.Pointer:
		return &ast.StarExpr{
			X: a.NewAstTypeExpr(t0.Elem()),
		}
	case *types.Named:
		return a.newPossiblyQualifiedTypeIdent(t0.Obj())
	case *types.Struct:
		return a.newAstStructTypeExpr(t0)
	default:
		panic(fmt.Sprintf("implement NewTypeExpr for %s", t.String()))
	}
}

// newAstStructTypeExpr returns the expression representing a struct type.
// The function may panic on unsupported types (see NewAwstTypeExpr).
func (a *AstBuildManager) newAstStructTypeExpr(t *types.Struct) ast.Expr {
	n := t.NumFields()
	var fields []*ast.Field
	for i := 0; i < n; i++ {
		f := t.Field(i)
		newField := &ast.Field{
			Names: []*ast.Ident{ast.NewIdent(f.Name())},
			Type:  a.NewAstTypeExpr(f.Type()),
			Tag:   nil,
		}
		fields = append(fields, newField)
	}
	res := &ast.StructType{
		Fields: &ast.FieldList{
			List: fields,
		},
		Incomplete: false,
	}
	return res
}

// NewSingleAssignDecl generates an assignment statement where the operator is `:=` and
// assigns a single variable with the provided name on the left hand side.
func NewSingleAssignDecl(name string, rhs ast.Expr) *ast.AssignStmt {
	return &ast.AssignStmt{
		Lhs: []ast.Expr{
			&ast.Ident{Name: name},
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{
			rhs,
		},
	}
}

// NewMultiAssignDecl returns an assignment statement where the operator is `=` and
// the expression is assigned to a tuple of identifiers with the provided names.
func NewMultiAssignDecl(names []string, rhs ast.Expr) *ast.AssignStmt {
	ids := make([]ast.Expr, len(names))
	for i, name := range names {
		ids[i] = &ast.Ident{Name: name}
	}
	return &ast.AssignStmt{
		Lhs: ids,
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{
			rhs,
		},
	}
}

// NewVarDecl returns a declaration for the provided var.
func (a *AstBuildManager) NewVarDecl(v *types.Var) *ast.DeclStmt {
	declStmt := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names: []*ast.Ident{ast.NewIdent(v.Name())},
					Type:  a.NewAstTypeExpr(v.Type()),
				},
			},
		},
	}
	return declStmt
}

// NewFieldList returns a list of fields for the given tuple type.
// This is used to created functions, the tuple can be the tuple of parameters
// or the tuple of returned types.
func (a *AstBuildManager) NewFieldList(host *types.Package, tuple *types.Tuple) *ast.FieldList {
	var fields []*ast.Field
	for i := 0; i < tuple.Len(); i++ {
		v := tuple.At(i)
		field := &ast.Field{
			Names: []*ast.Ident{ast.NewIdent(v.Name())},
			Type:  a.NewAstTypeExpr(v.Type()),
		}
		fields = append(fields, field)
	}

	return &ast.FieldList{
		List: fields,
	}
}

// NamedTypeModuloPointer is a named type or a pointer to a named type.
// The Named and Actual fields should both be non-nil.
// If the actual type is a pointer, then the type of the element is Named and
// IsRef is true.
// If the actual type is a named type, then Actual == Named and IsRef is false.
type NamedTypeModuloPointer struct {
	// Named is the named part of the type
	Named *types.Named
	// Actual is the actual type, either a (*types.Named) or (*types.Pointer)
	Actual types.Type
	// IsRef indicates whether the type is a pointer to a named type (true) or a named type (false)
	IsRef bool
}

// MakeInterfaceForClass generates an interface spec for the named type passed as argument.
// If the given type does not have any methods, the returns TypeSpec will not have any methods.
func (a *AstBuildManager) MakeInterfaceForClass(
	program *ssa.Program,
	host *types.Package,
	classLike NamedTypeModuloPointer,
) (string, *ast.TypeSpec) {
	methods := program.MethodSets.MethodSet(classLike.Actual)

	var interfaceMethods []*ast.Field
	if methods != nil {
		for i := 0; i < methods.Len(); i++ {
			method := methods.At(i)
			methodSig := method.Type().(*types.Signature)
			methodField := &ast.Field{
				Names: []*ast.Ident{{Name: method.Obj().Name()}},
				Type: &ast.FuncType{
					Params:  a.NewFieldList(host, methodSig.Params()),
					Results: a.NewFieldList(host, methodSig.Results()),
				},
			}
			interfaceMethods = append(interfaceMethods, methodField)
		}
	}

	interfaceName := fmt.Sprintf("%sInterface", classLike.Named.Obj().Name())
	return interfaceName, &ast.TypeSpec{
		Name: &ast.Ident{Name: interfaceName},
		Type: &ast.InterfaceType{
			Methods: &ast.FieldList{
				List: interfaceMethods,
			},
		},
	}
}

// newPossiblyQualifiedTypeIdent returns an identifiers for the given type object.
//
// If the type object is not in the targeted host, then the expression returned is a selector expression
// where the parent is the package of the type. This means the package should be imported somewhere.
//
// If the package is the same, or the host or the obj package information is nil, then a simple ast identifier
// is returned.
func (a *AstBuildManager) newPossiblyQualifiedTypeIdent(obj types.Object) ast.Expr {
	host := a.Package.Types
	if host == nil || obj.Pkg() == nil || host.Path() == obj.Pkg().Path() {
		return ast.NewIdent(obj.Name())
	}
	pkgName := a.managedImportName(obj)
	return &ast.SelectorExpr{
		X:   ast.NewIdent(pkgName),
		Sel: ast.NewIdent(obj.Name()),
	}
}

func (a *AstBuildManager) managedImportName(obj types.Object) string {
	objPkgPath := obj.Pkg().Path()
	// Check current file imports first
	for _, importSpec := range a.File.Imports {
		pathValue := formatutil.Unquote(importSpec.Path.Value)
		if pathValue == objPkgPath {
			if importSpec.Name != nil {
				return importSpec.Name.Name
			}
			return ExtractPkgNameFromPath(pathValue)
		}
	}
	// Check import has already been registered
	if importName, isImported := a.NewImports[objPkgPath]; isImported {
		if importName != "" {
			return importName
		}
		return obj.Pkg().Name()
	}

	pkgName := obj.Pkg().Name()
	namesInUse := make(map[string]bool)
	for _, importSpec := range a.File.Imports {
		pathValue := formatutil.Unquote(importSpec.Path.Value)
		localPkgName := ExtractPkgNameFromPath(pathValue)
		if importSpec.Name != nil {
			localPkgName = importSpec.Name.Name
		}
		namesInUse[localPkgName] = true
	}

	for pkgPath, name := range a.NewImports {
		if name != "" {
			namesInUse[name] = true
		} else {
			namesInUse[ExtractPkgNameFromPath(pkgPath)] = true
		}
	}

	for namesInUse[pkgName] {
		pkgName = "_" + pkgName
	}

	if pkgName == obj.Pkg().Name() {
		a.NewImports[objPkgPath] = "" // not a named import
	} else {
		a.NewImports[objPkgPath] = pkgName // will be named import
	}
	return pkgName
}
