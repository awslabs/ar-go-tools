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

// NewTypeExpr returns an AST expression that represents the type t.
//
// For example, the expression that represents a types.Struct will be of the form
// struct{...}.
//
// For an integer, the expression is an identifier 'int'
func NewTypeExpr(t types.Type) (dst.Expr, error) {
	switch t0 := t.(type) {
	case *types.Basic:
		return dst.NewIdent(t0.String()), nil
	case *types.Named:
		// TODO: manage imports
		return dst.NewIdent(t0.String()), nil
	case *types.Struct:
		return newStructTypeExpr(t0)
	default:
		panic(fmt.Sprintf("implement NewTypeExpr for %s", t.String()))
	}
}

// newStructTypeExpr returns the expression representing a struct type, or an error if it could not create that
// expression.
func newStructTypeExpr(t *types.Struct) (dst.Expr, error) {
	n := t.NumFields()
	var fields []*dst.Field
	for i := 0; i < n; i++ {
		f := t.Field(i)
		te, err := NewTypeExpr(f.Type())
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
