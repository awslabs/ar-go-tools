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
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/refactor/rewrite"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
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

// Options combines all the options that are used when loading programs.
type Options struct {
	// BuildMode is the mode used when creating the SSA from the packages.
	BuildMode ssa.BuilderMode
	// LoadTests is a flag indicating whether tests should be loaded with the program.
	LoadTests bool
	// ApplyRewrites is a flag indicating whether the standard source rewrites should be applied.
	ApplyRewrites bool
	// Platform indicates which platform the analysis is being performed on (sets GOOS in env).
	Platform string
	// PackageConfig is the options passed to packages.Load.
	// The GOOS  in the Env of the packageConfig is overridden by the Platform when Platform is set.
	PackageConfig *packages.Config
}

// Do loads a program on platform "platform" using the buildmode provided and the args.
// To understand how to specify the args, look at the documentation of packages.Load.
//
// The returned program has already been built.
func Do(options Options, args []string) (*ssa.Program, []*packages.Package, error) {

	packageConfig := options.PackageConfig
	if packageConfig == nil {
		packageConfig = &packages.Config{
			Mode:  PkgLoadMode,
			Tests: options.LoadTests,
		}
	}

	if options.Platform != "" {
		packageConfig.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", options.Platform))
	}

	// load, parse and type check the given packages
	initialPackages, err := packages.Load(packageConfig, args...)
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

// LoadTarget loads the target specified by the list of files provided. Return an analyzer state that has been
// initialized with the program if successful. The Target of that state will be set to the provided name.
func LoadTarget(
	name string,
	files []string,
	logger *config.LogGroup,
	cfg *config.Config,
	options Options) (*WholeProgramState, error) {
	if name != "" {
		// If it's a named target, need to change to project root's directory to properly load the target
		err := os.Chdir(cfg.Root())
		if err != nil {
			return nil, fmt.Errorf("failed to change to root dir: %s", err)
		}
	}
	startLoad := time.Now()
	logger.Infof(formatutil.Faint("Reading sources for target") + " " + name + "\n")
	wholeProgramState, err := NewWholeProgramState(name, options, files, logger, cfg)
	loadDuration := time.Since(startLoad)
	if err != nil {
		return nil, fmt.Errorf("failed to load whole program: %v", err)
	}
	logger.Infof("Loaded whole program state in %3.4f s", loadDuration.Seconds())
	return wholeProgramState, nil
}

// LoadTargetWithPointer loads the target specified by the list of files provided.
// Builds the program and then runs the pointer analysis to return a PointerState.
func LoadTargetWithPointer(
	name string,
	files []string,
	logger *config.LogGroup,
	cfg *config.Config,
	options Options) (*PointerState, error) {
	wp, err := LoadTarget(name, files, logger, cfg, options)
	if err != nil {
		return nil, err // context for load target is enough
	}
	return NewPointerState(wp)
}
