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

	"github.com/dave/dst"
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

// NewAstTypeExpr returns an AST expression that represents the type t.
//
// For example, the expression that represents a types.Struct will be of the form
// struct{...}.
//
// For an integer, the expression is an identifier 'int'
func NewAstTypeExpr(t types.Type) (ast.Expr, error) {
	switch t0 := t.(type) {
	case *types.Basic:
		return ast.NewIdent(t0.String()), nil
	case *types.Named:
		// TODO: manage imports
		return ast.NewIdent(t0.Obj().Name()), nil
	case *types.Struct:
		return newAstStructTypeExpr(t0)
	default:
		panic(fmt.Sprintf("implement NewTypeExpr for %s", t.String()))
	}
}

// newAstStructTypeExpr returns the expression representing a struct type, or an error if it could not create that
// expression.
func newAstStructTypeExpr(t *types.Struct) (ast.Expr, error) {
	n := t.NumFields()
	var fields []*ast.Field
	for i := 0; i < n; i++ {
		f := t.Field(i)
		te, err := NewAstTypeExpr(f.Type())
		if err != nil {
			return nil, err
		}
		newField := &ast.Field{
			Names: []*ast.Ident{ast.NewIdent(f.Name())},
			Type:  te,
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
	return res, nil
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
func NewVarDecl(v *types.Var) *ast.DeclStmt {
	tyExpr, err := NewAstTypeExpr(v.Type())
	if err != nil {
		panic(err) // TODO; implementation missing, should ensure this doesn't happen before release
	}
	declStmt := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names: []*ast.Ident{ast.NewIdent(v.Name())},
					Type:  tyExpr,
				},
			},
		},
	}
	return declStmt
}
