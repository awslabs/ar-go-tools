package staticcommands

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var Analyzer = &analysis.Analyzer{
	Name:     "nonstaticcommands",
	Doc:      "reports os.Exec commands that are not static",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

func run(pass *analysis.Pass) (interface{}, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}
	insp.Preorder(nodeFilter, func(node ast.Node) {
		call := node.(*ast.CallExpr)
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}

		_, ok = sel.X.(*ast.Ident)
		if !ok {
			return
		}

		obj := pass.TypesInfo.TypeOf(call).Underlying().String()
		fun := sel.Sel.Name
		if obj != "*os/exec.Cmd" && !(fun == "Command" || fun == "CommandContext") {
			return
		}

		args := call.Args
		if fun == "CommandContext" {
			// first argument is context.Context value
			args = args[1:]
		}
		for _, arg := range args {
			if !isStatic(pass, arg) {
				pass.Reportf(call.Pos(), "non-static os/exec.Command call")
				return
			}
		}
	})

	return nil, nil
}

func isStatic(pass *analysis.Pass, expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		info := pass.TypesInfo.ObjectOf(v)
		_, ok := info.(*types.Const)
		return ok
	case *ast.BinaryExpr:
		switch v.Op {
		// for string concatenation and integer addition
		case token.ADD:
			return isStatic(pass, v.X) && isStatic(pass, v.Y)
		default:
			return false
		}
	default:
		return false
	}
}
