package analysis

import (
	"fmt"
	"os"
	"sort"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const PkgLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedExportFile |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes |
	packages.NeedModule

func LoadProgram(config *packages.Config, platform string, buildmode ssa.BuilderMode, args []string) (*ssa.Program, error) {

	if config == nil {
		config = &packages.Config{
			Mode:  PkgLoadMode,
			Tests: false,
		}
	}

	if platform != "" {
		config.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", platform))
	}

	// load, parse and type check the given packages
	initialPackages, err := packages.Load(config, args...)
	if err != nil {
		return nil, err
	}

	if len(initialPackages) == 0 {
		return nil, fmt.Errorf("no packages")
	}

	if packages.PrintErrors(initialPackages) > 0 {
		return nil, fmt.Errorf("errors found, exiting")
	}

	// Construct SSA for all the packages we have loaded
	program, packages := ssautil.AllPackages(initialPackages, buildmode)

	for i, p := range packages {
		if p == nil {
			return nil, fmt.Errorf("cannot build SSA for package %s", initialPackages[i])
		}
	}

	// Build SSA for entire program
	program.Build()

	return program, nil
}

func AllPackages(funcs map[*ssa.Function]bool) []*ssa.Package {
	pkgs := make(map[*ssa.Package]bool)
	for f := range funcs {
		if f.Package() != nil {
			pkgs[f.Package()] = true
		}
	}
	pkglist := make([]*ssa.Package, 0, len(pkgs))
	for p := range pkgs {
		pkglist = append(pkglist, p)
	}
	sort.Slice(pkglist, func(i, j int) bool {
		return pkglist[i].Pkg.Path() < pkglist[j].Pkg.Path()
	})
	return pkglist
}
