package analysis

import (
	"fmt"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func LoadProgram(config *packages.Config, buildmode ssa.BuilderMode, args []string) (*ssa.Program, error) {
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
