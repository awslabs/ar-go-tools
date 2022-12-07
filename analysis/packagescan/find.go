package packagescan

import (
	"strings"

	"golang.org/x/tools/go/ssa"
)

// FindImporters searches the list of packages (pkglist) for any imports of the target
// package or packages.
// If exact==true, it will compare the Name() of each imported package to the target.
// This is useful for packages like reflect and unsafe, where you only want exact matches.
// If exact==false, it will see if the Path() of each imported package begins with the
// target.  This is useful for projects spanning multiple projects, such as
// github.com/aws/aws-sdk-go/
func FindImporters(pkglist []*ssa.Package, target string, exact bool) map[string]bool {
	output := make(map[string]bool, len(pkglist))
	for _, p := range pkglist {
		for _, i := range p.Pkg.Imports() {
			if exact && i.Name() == target || !exact && strings.HasPrefix(i.Path(), target) {
				output[p.Pkg.Path()] = true
			}
		}
	}
	return output
}
