package refactor

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"strings"

	ac "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/astfuncs"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/functional"
	"github.com/dave/dst"
	"github.com/dave/dst/decorator"
	"github.com/dave/dst/dstutil"
)

// InsertNilChecks inserts nil checks in all functions that contains @nonnil as comment for a parameter.
// If any error is encountered, then the function will be left as is.
func InsertNilChecks(packages []*decorator.Package) {
	WithScope(packages, nilCheckInsertTransform)
}

// nilCheckInsertTransform inserts nil checks at c when c is the toplevel block in a function and the parent function
// has parameters with comments that contain @nonnil
func nilCheckInsertTransform(fi *ac.FuncInfo, c *dstutil.Cursor) bool {
	if blockStmt, ok := c.Node().(*dst.BlockStmt); ok {
		parent := fi.NodeMap[blockStmt].Parent
		if parent == nil {
			fmt.Printf("Parent nil\n")
			return true
		}

		// Only change the first block directly under the function declaration
		if _, isParentFd := parent.Label.(*dst.FuncDecl); !isParentFd {
			return true
		}

		// Find all nil-checks to insert: all the parameters with a @nonnil comment
		// that have a nillable type
		var toInsert []*dst.Field
		for _, param := range fi.Decl.Type.Params.List {
			b := false
			for _, s := range param.Decorations().End.All() {
				if strings.Contains(s, "@nonnil") {
					b = true
					break
				}
			}

			if astParam, ok := fi.Decorator.Ast.Nodes[param].(*ast.Field); b && ok {
				paramType := fi.Package.TypesInfo.TypeOf(astParam.Type)
				if !ac.IsNillableType(paramType) {
					fmt.Fprintf(os.Stderr, "WARNING: %s cannot be nil, @nonnil is superfluous.\n",
						strings.Join(functional.Map(param.Names, func(i *dst.Ident) string { return i.Name }), ","))
					b = false
				}
			}

			if b {
				toInsert = append(toInsert, param)
			}
		}

		var newStmts []dst.Stmt
		for _, params := range toInsert {
			for _, param := range params.Names {
				newStmt, err := newNilCheckStmt(fi, param.Name)
				if err != nil {
					return true
				}
				if newStmt != nil {
					newStmts = append(newStmts, newStmt)
				}
			}
		}

		if len(newStmts) > 0 {
			body := &dst.BlockStmt{
				List:           append(newStmts, blockStmt.List...),
				RbraceHasNoPos: blockStmt.RbraceHasNoPos,
				Decs:           blockStmt.Decs,
			}
			c.Replace(body)
		}

		return false
	} else {
		return true
	}
}

// newNilCheckStmt returns a new if name == nil { .. } statement that checks whether the variable with name
// is nil. The body of the check depends on the type of the function. If the function returns an error, then
// the body will return an error. Otherwise, it will panic.
func newNilCheckStmt(fi *ac.FuncInfo, name string) (*dst.IfStmt, error) {
	cond := &dst.BinaryExpr{
		X:    &dst.Ident{Name: name},
		Op:   token.EQL,
		Y:    ac.NewNil(),
		Decs: dst.BinaryExprDecorations{},
	}

	var body *dst.BlockStmt
	var comments dst.NodeDecs

	// Function returns error: return an error when the select parameter is nil
	if declReturnsErrorLast(fi.Decl) {
		comments = dst.NodeDecs{Start: []string{"\n", "// this nil check has been automatically inserted"}}
		returns, err := generateReturnOnlyError(fi, fmt.Sprintf("%s: %s is nil", fi.Decl.Name.Name, name))
		if err != nil {
			return nil, fmt.Errorf("failed to generate results to return")
		}
		body = &dst.BlockStmt{
			List: []dst.Stmt{
				&dst.ReturnStmt{
					Results: returns,
					Decs:    dst.ReturnStmtDecorations{},
				},
			},
			RbraceHasNoPos: false,
			Decs:           dst.BlockStmtDecorations{},
		}
	} else {
		// Function doesn't return an error: the nil check will cause a panic
		comments = dst.NodeDecs{Start: []string{
			"\n",
			"// WARNING: the following automatically inserted nil panics, and may cause problems",
			"// TODO: consider making the return type of the function a tuple with an error"}}
		body = &dst.BlockStmt{
			List: []dst.Stmt{
				&dst.ExprStmt{X: ac.NewPanic(ac.NewFalse())},
			},
			RbraceHasNoPos: false,
			Decs:           dst.BlockStmtDecorations{},
		}
	}

	ifstmt := &dst.IfStmt{
		Init: nil, // no init needed
		Cond: cond,
		Body: body,
		Else: nil,
		Decs: dst.IfStmtDecorations{NodeDecs: comments},
	}
	return ifstmt, nil
}

// declReturnsErrorLast returns true if the return type of fd is a tuple where the last element is of type 'error'
func declReturnsErrorLast(fd *dst.FuncDecl) bool {
	if fd.Type == nil || fd.Type.Results == nil {
		return false
	}
	results := fd.Type.Results.List
	if len(results) == 0 {
		return false
	}
	lastRes := results[len(results)-1]
	if lastRes.Type == nil {
		return false
	}
	if id, isId := lastRes.Type.(*dst.Ident); isId {
		if id.Name == "error" {
			return true
		}
	}
	return false
}

func generateReturnOnlyError(fi *ac.FuncInfo, msg string) ([]dst.Expr, error) {
	fd := fi.Decl
	if !declReturnsErrorLast(fd) {
		return nil, fmt.Errorf("%s does not return an error", fd.Name.Name)
	}

	var results []dst.Expr
	for _, resultType := range fd.Type.Results.List {
		if id, isId := resultType.Type.(*dst.Ident); isId && id.Name == "error" {
			// e is fmt.Errorf(msg)
			e := &dst.CallExpr{
				Fun: &dst.Ident{
					Name: "Errorf",
					Obj:  nil,
					Path: "fmt",
					Decs: dst.IdentDecorations{},
				},
				Args: []dst.Expr{ac.NewString(msg)},
			}
			results = append(results, e)
		} else {
			typNode := fi.Decorator.Map.Ast.Nodes[resultType].(*ast.Field).Type
			typ := fi.Package.TypesInfo.TypeOf(typNode)
			zeroVal, err := ac.ZeroValueExpr(typ)
			if err != nil {
				return nil, err
			}
			results = append(results, zeroVal)
		}
	}
	return results, nil
}
