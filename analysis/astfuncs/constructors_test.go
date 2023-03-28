package astfuncs

import (
	"go/token"
	"testing"

	"github.com/dave/dst"
)

func TestExpr(t *testing.T) {
	a := dst.NewIdent("a")
	b := dst.NewIdent("b")
	aPlusB := NewBinOp(token.ADD, a, b)
	minusAplusB := NewUnOp(token.SUB, aPlusB)
	t.Logf("[-(a+b)] -> %s", minusAplusB) // TODO: write or find a function to print single expressions
}
