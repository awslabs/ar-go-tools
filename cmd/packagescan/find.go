package main

import (
	"go/types"
	"io"
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
func FindImporters(pkglist []*ssa.Package, target string, exact bool, rawfile io.WriteCloser) map[string]bool {
	output := make(map[string]bool, len(pkglist))
	for _, p := range pkglist {
		if target == "" || matchImport(target, exact, p.Pkg.Imports()) {
			output[p.Pkg.Path()] = true
			if rawfile != nil {
				dumpSymbols(p, target, exact, rawfile)
			}
		}
	}
	return output
}

func matchImport(target string, exact bool, imports []*types.Package) bool {
	for _, i := range imports {
		if exact && i.Name() == target || !exact && strings.HasPrefix(i.Path(), target) {
			return true
		}
	}
	return false
}

func dumpSymbols(p *ssa.Package, target string, exact bool, rawfile io.WriteCloser) {
	// placeholder to dump any uses of a symbol to output.  Ignores the fact
	// that we should probably emit the platform... which we don't have here.
	// we might need to go back and create separate rawfiles for each platform
	// or only enable rawfile when used with a single platform.  or ignore it
	// and allow duplicate entries.
}
