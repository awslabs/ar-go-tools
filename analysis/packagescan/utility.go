package packagescan

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"strings"

	"golang.org/x/tools/go/ssa"

	. "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/functional"
)

// at this point, the f.String contains something like this:
// (*net/http.requestBodyReadError).Error
// (encoding/json.jsonError).Error
// (*github.com/aws/aws-sdk-go/aws/endpoints.EndpointNotFoundError).Error

func packageFromErrorName(name string) string {
	if !strings.HasSuffix(name, ").Error") {
		return ""
	}
	name = name[:len(name)-7]
	if !strings.HasPrefix(name, "(") {
		return ""
	}
	name = name[1:]
	if strings.HasPrefix(name, "*") {
		name = name[1:]
	}
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[:i]
}

func PackageTypeFromFunction(f *ssa.Function) *types.Package {
	pkg := f.Package()
	if pkg != nil {
		return pkg.Pkg
	}

	obj := f.Object().Pkg()
	if obj != nil {
		return obj
	}

	// could just return obj, but we're explicit about returning nil
	return nil
}

func PackageNameFromFunction(f *ssa.Function) string {
	if f == nil {
		return ""
	}

	pkg := f.Package()
	if pkg != nil {
		return pkg.Pkg.Path()
	}

	// this is a method, so need to get its Object first
	obj := f.Object().Pkg()
	if obj != nil {
		return obj.Path()
	}

	name := packageFromErrorName(f.String())
	if name != "" {
		return name
	}

	fmt.Fprintln(os.Stderr, "Object Package is nil", f.String())
	return ""
}

// DummyPos is a dummy position returned to indicate that no position could be found. Can also be used when generating
// code, and the generated code has no position.
var DummyPos = token.Position{
	Filename: "unknown",
	Offset:   -1,
	Line:     -1,
	Column:   -1,
}

func SafeFunctionPos(function *ssa.Function) Optional[token.Position] {
	if function.Prog != nil && function.Prog.Fset != nil {
		return Some(function.Prog.Fset.Position(function.Pos()))
	} else {
		return None[token.Position]()
	}
}
