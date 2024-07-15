// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analysis

import (
	"fmt"
	"os"
	"sort"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// PkgLoadMode is the default loading mode in the analyses. We load all possible information
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

// LoadProgram loads a program on platform "platform" using the buildmode provided and the args.
// To understand how to specify the args, look at the documentation of packages.Load.
func LoadProgram(config *packages.Config,
	platform string,
	buildmode ssa.BuilderMode,
	args []string) (*ssa.Program, []*packages.Package, error) {

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
		return nil, nil, err
	}

	if len(initialPackages) == 0 {
		return nil, nil, fmt.Errorf("no packages")
	}

	if packages.PrintErrors(initialPackages) > 0 {
		return nil, nil, fmt.Errorf("errors found, exiting")
	}

	// Construct SSA for all the packages we have loaded
	program, ssaPackages := ssautil.AllPackages(initialPackages, buildmode)

	for i, p := range ssaPackages {
		if p == nil {
			return nil, nil, fmt.Errorf("cannot build SSA for package %s", initialPackages[i])
		}
	}

	// Build SSA for entire program
	program.Build()

	return program, initialPackages, nil
}

// AllPackages returns the slice of all packages the set of functions provided as argument belong to.
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
