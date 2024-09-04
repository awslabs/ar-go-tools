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

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
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
	loadTests bool,
	args []string) (*ssa.Program, []*packages.Package, error) {

	if config == nil {
		config = &packages.Config{
			Mode:  PkgLoadMode,
			Tests: loadTests,
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

// LoadAnalyzerState is like LoadProgram but additionally wraps the loaded program in a simple analyzer state.
// Does not run pointer analysis for example.
func LoadAnalyzerState(pkgConfig *packages.Config,
	platform string,
	buildmode ssa.BuilderMode,
	loadTests bool,
	args []string, cfg *config.Config) (*dataflow.AnalyzerState, error) {
	program, pkgs, err := LoadProgram(pkgConfig, platform, buildmode, loadTests, args)
	if err != nil {
		return nil, fmt.Errorf("could not load program: %v", err)
	}
	state, err := dataflow.NewAnalyzerState(program, pkgs,
		config.NewLogGroup(cfg), cfg, []func(state *dataflow.AnalyzerState){})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize analyzer state: %s", err)
	}
	return state, nil
}

// AllPackages returns the slice of all packages the set of functions provided as argument belong to.
func AllPackages(funcs map[*ssa.Function]bool) []*ssa.Package {
	pkgs := make(map[*ssa.Package]bool)
	for f := range funcs {
		if f.Package() != nil {
			pkgs[f.Package()] = true
		}
	}
	pkgList := make([]*ssa.Package, 0, len(pkgs))
	for p := range pkgs {
		pkgList = append(pkgList, p)
	}
	sort.Slice(pkgList, func(i, j int) bool {
		return pkgList[i].Pkg.Path() < pkgList[j].Pkg.Path()
	})
	return pkgList
}
