package refactor

import (
	ac "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/astfuncs"
	"github.com/dave/dst"
	"github.com/dave/dst/decorator"
	"github.com/dave/dst/dstutil"
)

type Transform func(*ac.FuncInfo, *dstutil.Cursor) bool

// buildScopeTree collects information about the AST and links children nodes to parent nodes in the funcInfo.NodeMap
func buildScopeTree(funcInfo *ac.FuncInfo, c *dstutil.Cursor) bool {
	n := c.Node()
	p := c.Parent()
	if n != nil && p != nil {
		if parent, ok := funcInfo.NodeMap[p]; ok {
			cur := &ac.NodeTree{Parent: parent, Label: n}
			funcInfo.NodeMap[n] = cur
		}
	}
	return true
}

// WithScope applies the transform post to packages as a post operation in Apply. It first runs the function
// that builds information necessary to have access to closest scopes within a function.
// The post transform can use the FuncInfo's various scope operations
func WithScope(packages []*decorator.Package, post Transform) {
	for _, pack := range packages {
		for _, dstFile := range pack.Syntax {
			// Create a new decorator, which will track the mapping between ast and dst nodes
			for _, decl := range dstFile.Decls {
				if funcDecl, ok := decl.(*dst.FuncDecl); ok {
					m := map[dst.Node]*ac.NodeTree{}
					root := &ac.NodeTree{Parent: nil, Label: funcDecl}
					m[funcDecl] = root
					fi := &ac.FuncInfo{
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
