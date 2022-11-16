package analysis

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/tools/go/ssa"
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

func PackageNameFromFunction(f *ssa.Function) string {
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
