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

package loadprogram

import (
	"fmt"
	"os"
	"sort"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/refactor/rewrite"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Do loads a program on platform "platform" using the buildmode provided and the args.
// To understand how to specify the args, look at the documentation of packages.Load.
//
// The returned program has already been built.
func do(files []string, options config.LoadOptions) (*ssa.Program, []*packages.Package, error) {

	packageConfig := options.PackageConfig
	if packageConfig == nil {
		packageConfig = &packages.Config{
			Mode:  config.PkgLoadMode,
			Tests: options.LoadTests,
		}
	}

	if options.Platform != "" {
		packageConfig.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", options.Platform))
	}

	// load, parse and type check the given packages
	initialPackages, err := packages.Load(packageConfig, files...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load program: %s", err)
	}

	if len(initialPackages) == 0 {
		return nil, nil, fmt.Errorf("no packages")
	}

	if options.ApplyRewrites {
		// Apply rewrites improving precision
		rewrite.ApplyRewrites(initialPackages)
	}

	if packages.PrintErrors(initialPackages) > 0 {
		return nil, nil, fmt.Errorf("errors found, exiting")
	}

	// Construct SSA for all the packages we have loaded
	program, ssaPackages := ssautil.AllPackages(initialPackages, options.BuildMode)

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
	pkgList := make([]*ssa.Package, 0, len(pkgs))
	for p := range pkgs {
		pkgList = append(pkgList, p)
	}
	sort.Slice(pkgList, func(i, j int) bool {
		return pkgList[i].Pkg.Path() < pkgList[j].Pkg.Path()
	})
	return pkgList
}
