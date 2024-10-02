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

// Copyright 2023 The Go Authors. All rights reserved.
// Modifications Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rewrite

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/packages"
)

type matcher interface {
	// match checks if a CallExpr is a call to a particular function or method
	// that this object is looking for.  If it matches, it returns a particular
	// argument in the call that has a function type.  Otherwise it returns nil.
	match(*types.Info, *ast.CallExpr) ast.Expr
}

// packageFunctionMatcher objects match a package-scope function.
type packageFunctionMatcher struct {
	pkg                         string
	functionName                string
	functionTypedParameterIndex int
}

// methodMatcher objects match a method of some type.
type methodMatcher struct {
	pkg                         string
	typeName                    string
	methodName                  string
	functionTypedParameterIndex int
}

func (m *packageFunctionMatcher) match(typeInfo *types.Info, call *ast.CallExpr) ast.Expr {
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		// The function to be called is not a selection, so it can't be a call to
		// the relevant package.  (Unless the user has dot-imported the package,
		// but we don't need to worry much about false negatives in unusual cases
		// here.)
		return nil
	}
	pkgIdent, ok := callee.X.(*ast.Ident)
	if !ok {
		// The left-hand side of the selection is not a plain identifier.
		return nil
	}
	pkgName, ok := typeInfo.Uses[pkgIdent].(*types.PkgName)
	if !ok {
		// The identifier does not refer to a package.
		return nil
	}
	if pkgName.Imported().Path() != m.pkg {
		// Not the right package.
		return nil
	}
	if name := callee.Sel.Name; name != m.functionName {
		// This isn't the function we're looking for.
		return nil
	}
	if len(call.Args) <= m.functionTypedParameterIndex {
		// The function call doesn't have enough arguments.
		return nil
	}
	return call.Args[m.functionTypedParameterIndex]
}

// mayHaveSideEffects determines whether an expression might write to a
// variable or call a function.  It can have false positives.  It does not
// consider panicking to be a side effect, so e.g. index expressions do not
// have side effects unless one of its components do.
//
// This is used to determine whether we can delete the expression from the
// syntax tree in isCallToOnceDoEtc.
//
//gocyclo:ignore
func mayHaveSideEffects(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.Ident, *ast.BasicLit:
		return false
	case nil:
		return false // we can reach a nil via *ast.SliceExpr
	case *ast.FuncLit:
		return false // a definition doesn't do anything on its own
	case *ast.CallExpr:
		return true
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if mayHaveSideEffects(elt) {
				return true
			}
		}
		return false
	case *ast.ParenExpr:
		return mayHaveSideEffects(e.X)
	case *ast.SelectorExpr:
		return mayHaveSideEffects(e.X)
	case *ast.IndexExpr:
		return mayHaveSideEffects(e.X) || mayHaveSideEffects(e.Index)
	case *ast.IndexListExpr:
		for _, idx := range e.Indices {
			if mayHaveSideEffects(idx) {
				return true
			}
		}
		return mayHaveSideEffects(e.X)
	case *ast.SliceExpr:
		return mayHaveSideEffects(e.X) ||
			mayHaveSideEffects(e.Low) ||
			mayHaveSideEffects(e.High) ||
			mayHaveSideEffects(e.Max)
	case *ast.TypeAssertExpr:
		return mayHaveSideEffects(e.X)
	case *ast.StarExpr:
		return mayHaveSideEffects(e.X)
	case *ast.UnaryExpr:
		return mayHaveSideEffects(e.X)
	case *ast.BinaryExpr:
		return mayHaveSideEffects(e.X) || mayHaveSideEffects(e.Y)
	case *ast.KeyValueExpr:
		return mayHaveSideEffects(e.Key) || mayHaveSideEffects(e.Value)
	}
	return true
}

func (m *methodMatcher) match(typeInfo *types.Info, call *ast.CallExpr) ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if mayHaveSideEffects(sel.X) {
		// The expression may be something like foo().Do(bar), which we can't
		// rewrite to a call to bar because then the analysis would not see the
		// call to foo.
		return nil
	}
	calleeType := typeInfo.TypeOf(sel.X)
	if calleeType == nil {
		return nil
	}
	if ptr, ok := calleeType.(*types.Pointer); ok {
		calleeType = ptr.Elem()
	}
	named, ok := calleeType.(*types.Named)
	if !ok {
		return nil
	}
	if named.Obj().Pkg() != nil {
		if pkg := named.Obj().Pkg().Path(); pkg != m.pkg {
			// Not the right package.
			return nil
		}
	}
	if named.Obj().Name() != m.typeName {
		// Not the right type.
		return nil
	}
	if name := sel.Sel.Name; name != m.methodName {
		// Not the right method.
		return nil
	}
	if len(call.Args) <= m.functionTypedParameterIndex {
		// The method call doesn't have enough arguments.
		return nil
	}
	return call.Args[m.functionTypedParameterIndex]
}

// visitor is passed to ast.Visit, to find AST nodes where
// unsafe.Pointer values are converted to pointers.
// It satisfies the ast.Visitor interface.
type visitor struct {
	// The sets we are populating.
	unsafeFunctionNodes map[ast.Node]struct{}
	// Set to true if an unsafe.Pointer conversion is found that is not inside
	// a function, method, or function literal definition.
	seenUnsafePointerUseInInitialization *bool
	// The Package for the ast Node being visited.  This is used to get type
	// information.
	pkg *packages.Package
	// The node for the current function being visited.  When function definitions
	// are nested, this is the innermost function.
	currentFunction ast.Node // *ast.FuncDecl or *ast.FuncLit
}

// containsReflectValue returns true if t is reflect.Value, or is a struct
// or array containing reflect.Value.
func containsReflectValue(t types.Type) bool {
	seen := map[types.Type]struct{}{}
	var rec func(t types.Type) bool
	rec = func(t types.Type) bool {
		if t == nil {
			return false
		}
		if t.String() == "reflect.Value" {
			return true
		}
		// avoid an infinite loop if the type is recursive somehow.
		if _, ok := seen[t]; ok {
			return false
		}
		seen[t] = struct{}{}
		// If the underlying type is different, use that.
		if u := t.Underlying(); !types.Identical(t, u) {
			return rec(u)
		}
		// Check fields of structs.
		if s, ok := t.(*types.Struct); ok {
			for i := 0; i < s.NumFields(); i++ {
				if rec(s.Field(i).Type()) {
					return true
				}
			}
		}
		// Check elements of arrays.
		if a, ok := t.(*types.Array); ok {
			return rec(a.Elem())
		}
		return false
	}
	return rec(t)
}

func (v *visitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return v // the return value is ignored if node == nil.
	}
	switch node := node.(type) {
	case *ast.FuncDecl, *ast.FuncLit:
		// The subtree at this node is a function definition or function literal.
		// The visitor returned here is used to visit this node's children, so we
		// return a visitor with the current function set to this node.
		v2 := *v
		v2.currentFunction = node
		return &v2
	case *ast.CallExpr:
		// A type conversion is represented as a CallExpr node with a Fun that is a
		// type, and Args containing the expression to be converted.
		//
		// If this node has a single argument which is an unsafe.Pointer (or
		// is equivalent to an unsafe.Pointer) and the callee is a type which is not
		// uintptr, we add the current function to v.unsafeFunctionNodes.
		funType := v.pkg.TypesInfo.Types[node.Fun]
		if !funType.IsType() {
			// The callee is not a type; it's probably a function or method.
			break
		}
		if b, ok := funType.Type.Underlying().(*types.Basic); ok && b.Kind() == types.Uintptr {
			// The conversion is to a uintptr, not a pointer.  On its own, this is
			// safe.
			break
		}
		var args = node.Args
		if len(args) != 1 {
			// There wasn't the right number of arguments.
			break
		}
		argType := v.pkg.TypesInfo.Types[args[0]].Type
		if argType == nil {
			// The argument has no type information.
			break
		}
		if b, ok := argType.Underlying().(*types.Basic); !ok || b.Kind() != types.UnsafePointer {
			// The argument's type is not equivalent to unsafe.Pointer.
			break
		}
		if v.currentFunction == nil {
			*v.seenUnsafePointerUseInInitialization = true
		} else {
			v.unsafeFunctionNodes[v.currentFunction] = struct{}{}
		}
	}
	return v
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
