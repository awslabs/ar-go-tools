package astfuncs

import "github.com/dave/dst"

// This file contains function to manage variable names within the scope of an existing program
// To create a new variable with name in the same scope as node n, use NewIdent(n, name).

import (
	"fmt"
	"go/token"
	"go/types"

	"github.com/dave/dst/decorator"
)

type NodeTree struct {
	Parent *NodeTree
	Label  dst.Node
}

// FuncInfo contains information about a function declaration in the ast.
type FuncInfo struct {
	// Package is the package where the function is declared
	Package *decorator.Package

	// Decorator is the decorator object that contains also the maps from dst to ast objects
	Decorator *decorator.Decorator

	// File if the file where the function is declared
	File *dst.File

	// NodeMap stores parent information for the ast
	NodeMap map[dst.Node]*NodeTree

	// Decl is the function declaration in the ast
	Decl *dst.FuncDecl
}

// FunctionScope returns the scope of the function
func (f *FuncInfo) FunctionScope() *types.Scope {
	declType := f.Decorator.Ast.Nodes[f.Decl.Type]
	return f.Package.TypesInfo.Scopes[declType]
}

// ClosestEnclosingScope returns the closest scope to the node n.
//
// For example, in :
//
//	func f(..) {
//	  if(b) {
//	     node1
//	  } else {
//	    node2
//	  }
//	  node 3
//	}
//
// the closest scope for node1 is the then-branch scope, for node2 the else-brnach scope
// and for node3 the function scope
func (f *FuncInfo) ClosestEnclosingScope(n dst.Node) *types.Scope {
	if nodeT, ok := f.NodeMap[n]; ok {
		for cur := nodeT; cur != nil; cur = cur.Parent {
			curLabel := f.Decorator.Ast.Nodes[cur.Label]
			if scope, ok := f.Package.TypesInfo.Scopes[curLabel]; ok {
				return scope
			}
		}
		return nil
	}
	return nil
}

// NameExistsAt checks whether name is a declared identifier at node n
func (f *FuncInfo) NameExistsAt(n dst.Node, name string) bool {
	// Get the closest scope to n
	scope := f.ClosestEnclosingScope(n)
	if scope != nil {
		return isInSomeParentScope(scope, name)
	}
	// If scope is not found, use function scope
	scope = f.FunctionScope()
	if scope != nil {
		return isInSomeParentScope(scope, name)
	}
	// In last resort, use file scope
	if f.File.Scope.Lookup(name) != nil {
		return true
	}
	return false
}

// FreshNameAt returns a fresh identifier at node n. The identifier will be of the form `prefix(NUM)` where
// NUM is empty or some interger. For example, FreshNameAt(n,"s", 0) may return "s", "s0" or "s1".
func (f *FuncInfo) FreshNameAt(n dst.Node, prefix string, i int) string {
	name := prefix
	if i > 0 {
		name = fmt.Sprintf("%s%d", prefix, i)
	}
	for {
		if f.NameExistsAt(n, name) {
			i++
			name = fmt.Sprintf("%s%d", prefix, i)
		} else {
			return name
		}
	}

}

// NewIdent returns a new identifier that is a fresh name at node n. If successful, the scope should be non-nil and
// addition of the identifier in the program should be done by adding the identifier to the scope returned (if the
// intention is to declare the identifier next to n).
func (f *FuncInfo) NewIdent(n dst.Node, prefix string) (*types.Scope, string) {
	varName := f.FreshNameAt(n, prefix, 0)
	scope := f.ClosestEnclosingScope(n)
	return scope, varName
}

func isInSomeParentScope(scope *types.Scope, s string) bool {
	_, o := scope.LookupParent(s, token.NoPos)
	if o != nil {
		return true
	} else {
		return false
	}
}
