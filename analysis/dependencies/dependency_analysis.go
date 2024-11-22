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

package dependencies

import (
	//	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/reachability"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// isDependency checks whether the function is a dependency (not stdlib):
//
// Returns true, isIndirect, moduleName when it is a dependency. `isIndirect` is true when the dependency is indirect.
// This requires having module information.
//
// Returns false, _, _ when it is not a dependency.
func isDependency(modules map[string]*packages.Module, f *ssa.Function) (bool, bool, string) {
	packagePath := lang.PackageNameFromFunction(f)
	if packagePath == "" {
		return false, false, ""
	}
	//	packagePath := f.Pkg.Pkg.Path()
	split := strings.Split(packagePath, "/")
	// Uses modules information first
	for i := len(split) - 1; i >= 3; i-- {
		if module, hasModule := modules[strings.Join(split[0:i], "/")]; hasModule {
			return true, module.Indirect, module.Path
		}
	}

	// Then use heuristics to guess the dependency (e.g. modules are not loaded).
	// Always assume it's direct in this case.
	if len(split) >= 3 {
		if strings.Index(split[0], ".") == -1 {
			// no dot in the first component, e.g., "runtime"
			return false, false, packagePath
		}
		// dot found, e.g. github.com
		return true, false, split[0] + "/" + split[1] + "/" + split[2]
	}
	return false, false, packagePath
}

func calculateLocs(f *ssa.Function) uint {

	var numberOfInstructions uint = 0

	for _, b := range f.Blocks {
		numberOfInstructions += uint(len(b.Instrs))
	}

	return numberOfInstructions
}

// computePath attempts to find the canonical name for a file by merging the on-disk
// full path to the source file with the Go-provided package name.
// if we could get the init string out of go.mod, we could just leverage that,
// but that doesn't appear to be exposed in SSA.
// we could probably be a bit more efficient by computing the prefix and caching it,
// but this seems to be the most general approach for now.
func computePath(cfg *config.Config, logger *config.LogGroup, filepath string, pkg string) string {
	verbose := cfg.PkgFilter != "" && strings.Contains(pkg, cfg.PkgFilter) || cfg.PkgFilter == "*"
	if verbose {
		logger.Debugf("computePath(%q,%q)=", filepath, pkg)
	}
	// if the full package name appears in the filepath, then just chop off the prefix
	// and return the full packagename with the path within the package.
	offset := strings.Index(filepath, pkg)
	if offset >= 0 {
		if verbose {
			logger.Debugf("1: %s", filepath[offset:])
		}
		return filepath[offset:]
	}

	// if the full package name does not appear, we have a situation where the
	// filepath doesn't contain the full repo.  This is common when the go.mod contains
	// the actual root of the project e.g.
	//   filepath = packageX/packageY/foo.go
	//   pkg = github.com/org/packageX/packageY
	// we need to iterate through progressively removing the initial elements from the package name
	// until we find a match.
	split := 0
	for {
		newsplit := strings.Index(pkg[split:], "/")
		if newsplit == -1 {
			if verbose {
				logger.Debugf(filepath)
			}
			return filepath // bail
		}
		split = split + newsplit
		offset = strings.Index(filepath, pkg[split:])
		if offset >= 0 {
			if verbose {
				logger.Debugf(pkg[:split] + filepath[offset:])
			}
			return pkg[:split] + filepath[offset:]
		}
		split++ // skip the "/"
	}
}

func emitCoverageLine(state *loadprogram.State, dest io.Writer, f *ssa.Function, reachable bool, locs uint) {
	if f == nil || f.Package() == nil {
		return
	}
	syn := f.Syntax()
	if syn == nil {
		return
	}

	start := state.Program.Fset.Position(syn.Pos())
	end := state.Program.Fset.Position(syn.End())

	newname := computePath(state.Config, state.Logger, start.Filename, f.Package().Pkg.Path())

	reachval := 0
	if reachable {
		reachval = 1
	}

	str := fmt.Sprintf("%s:%d.%d,%d.%d %d %d\n", newname, start.Line, start.Column,
		end.Line, end.Column, locs, reachval)

	dest.Write([]byte(str[:]))

}

// DependencyConfigs contains output settings for the dependency analysis.
type DependencyConfigs struct {
	// JsonFlag indicates whether the output should be Json-formatted (TODO).
	JsonFlag bool
	// IncludeStdlib indicates whether the standard library should be included in the analysis.
	IncludeStdlib bool
	// CoverageFile is a writer that will contain the coverage data if non-nil.
	CoverageFile io.Writer
	// CsvFile is a writer that will contain the list of dependency usage if non-nil.
	CsvFile io.Writer
	// UsageThreshold is a dependency usage percentage threshold below which a warning is produced.
	UsageThreshold float64
	// LocThreshold is an absolute dependency usage threshold below which a warning is produced
	LocThreshold int
	// ComputeGraph indicates whether the dependency graph should be computed.
	ComputeGraph bool
}

// count reachable and unreachable LOCs, per dependency
type dependencyStats struct {
	reachableLocs   uint
	unreachableLocs uint
	isIndirect      bool
}

// DependencyAnalysis runs the dependency analysis on all the functions in the ssa.Program
// Writes a coverage file in covFile indicating which functions are reachable.
func DependencyAnalysis(state *loadprogram.State, dc DependencyConfigs) reachability.DependencyGraph {
	// Collect modules
	modules := make(map[string]*packages.Module)
	packages.Visit(state.Packages, nil, func(pack *packages.Package) {
		if pack.Types != nil && !pack.IllTyped {
			if pack.Module != nil {
				if _, reg := modules[pack.Module.Path]; !reg {
					state.Logger.Debugf("Found module %s (indirect: %v)", pack.Module.Path, pack.Module.Indirect)
					modules[pack.Module.Path] = pack.Module
				}
			}
		}
	})

	// all functions we have got
	allFunctions := ssautil.AllFunctions(state.Program)

	var dependencyGraph reachability.DependencyGraph = nil
	if dc.ComputeGraph {
		dependencyGraph = reachability.NewDependencyGraph()
	}

	// functions known to be reachable
	reachable := reachability.FindReachable(state, false, false, dependencyGraph)

	dependencyMap := make(map[string]dependencyStats)
	var maxLoc uint = 0 // for formatting output
	for f := range allFunctions {
		ok, isIndirect, id := isDependency(modules, f)
		if ok || dc.IncludeStdlib {
			entry := dependencyMap[id]
			locs := calculateLocs(f)
			entry.isIndirect = isIndirect
			// is it reachable?
			_, isReachable := reachable[f]
			if isReachable {
				entry.reachableLocs += locs
			} else {
				entry.unreachableLocs += locs
			}
			maxLoc = max(entry.reachableLocs, maxLoc)
			if dc.CoverageFile != nil {
				emitCoverageLine(state, dc.CoverageFile, f, isReachable, locs)
			}

			dependencyMap[id] = entry
		}
	}

	// order alphabetically
	dependencyNames := make([]string, 0, len(dependencyMap))
	for key := range dependencyMap {
		dependencyNames = append(dependencyNames, key)
	}

	depNameMaxLen := 0 // recorded for formatting output
	sort.Slice(dependencyNames, func(i, j int) bool {
		d1 := dependencyNames[i]
		d2 := dependencyNames[j]
		depNameMaxLen = max(depNameMaxLen, len(d1), len(d2))
		return compareDeps(d1, d2, dependencyMap)
	})

	maxLocLen := len(fmt.Sprintf("%d", maxLoc))
	// output
	state.Logger.Infof("Dependencies (direct or indirect, name, reachable LOC, total LOC, %% LOC usage):")
	for _, dependencyName := range dependencyNames {
		entry := dependencyMap[dependencyName]
		total := entry.reachableLocs + entry.unreachableLocs
		percentage := (100.0 * float64(entry.reachableLocs)) / float64(total)

		printDependencyUsageSummary(state, dc, dependencyName, depNameMaxLen, maxLocLen, total, entry, percentage)

		if dc.CsvFile != nil {
			dc.CsvFile.Write([]byte(fmt.Sprintf("%s,%v,%d,%d,%3.2f\n",
				dependencyName, !entry.isIndirect, entry.reachableLocs, total, percentage)))
		}
	}

	return dependencyGraph
}

func compareDeps(d1 string, d2 string, dependencyMap map[string]dependencyStats) bool {
	if !dependencyMap[d1].isIndirect && dependencyMap[d2].isIndirect {
		return true
	}
	if dependencyMap[d1].isIndirect && !dependencyMap[d2].isIndirect {
		return false
	}
	return d1 < d2
}

func printDependencyUsageSummary(state *loadprogram.State, dc DependencyConfigs,
	dependencyName string, depNameMaxLen int, maxLocLen int, total uint, entry dependencyStats, percentage float64) {

	msgIndirect := formatutil.Bold(" direct ")
	if entry.isIndirect {
		msgIndirect = formatutil.Faint("indirect")
	}

	msg := fmt.Sprintf("%s %s %s %s ",
		msgIndirect,
		fmt.Sprintf("%-*s", depNameMaxLen, dependencyName), // padded dependency name
		fmt.Sprintf("%-*d", maxLocLen, entry.reachableLocs),
		fmt.Sprintf("%-*s", maxLocLen, fmt.Sprintf("%d", total)),
	)

	// the condition for warning
	needsWarning := !entry.isIndirect && (int(entry.reachableLocs) < dc.LocThreshold && percentage < dc.UsageThreshold)

	var percentageFormatted string
	if needsWarning {
		percentageFormatted = formatutil.Red(fmt.Sprintf("(%3.1f %%)", percentage))
	} else {
		percentageFormatted = fmt.Sprintf("(%3.1f %%)", percentage)
	}
	msg += percentageFormatted
	if needsWarning {
		warnMsg := fmt.Sprintf(" <- less than %d lines used, and below %3.1f %% usage",
			dc.LocThreshold, dc.UsageThreshold)
		state.Logger.Warnf("%s %s\n", formatutil.Red(msg), warnMsg)
	} else {
		state.Logger.Infof("%s\n", msg)
	}
}
