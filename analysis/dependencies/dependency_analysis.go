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
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/reachability"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func isDependency(f *ssa.Function) (bool, string) {
	packagePath := lang.PackageNameFromFunction(f)
	if packagePath == "" {
		return false, ""
	}
	//	packagePath := f.Pkg.Pkg.Path()
	split := strings.Split(packagePath, "/")
	if len(split) >= 3 {
		if strings.Index(split[0], ".") == -1 {
			// no dot in the first component, e.g., "runtime"
			return false, packagePath
		}
		// dot found, e.g. github.com
		return true, split[0] + "/" + split[1] + "/" + split[2]
	}
	return false, packagePath
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

func emitCoverageLine(state *dataflow.AnalyzerState, dest io.Writer, f *ssa.Function, reachable bool, locs uint) {
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
	// ComputeGraph indicates whether the dependency graph should be computed.
	ComputeGraph bool
}

// DependencyAnalysis runs the dependency analysis on all the functions in the ssa.Program
// Writes a coverage file in covFile indicating which functions are reachable.
func DependencyAnalysis(state *dataflow.AnalyzerState,
	dc DependencyConfigs) reachability.DependencyGraph {

	// all functions we have got
	allFunctions := ssautil.AllFunctions(state.Program)

	var dependencyGraph reachability.DependencyGraph = nil
	if dc.ComputeGraph {
		dependencyGraph = reachability.NewDependencyGraph()
	}

	// functions known to be reachable
	reachable := reachability.FindReachable(state.Program, false, false, dependencyGraph)

	// count reachable and unreachable LOCs, per dependency
	type dependency struct {
		reachableLocs   uint
		unreachableLocs uint
	}

	dependencyMap := make(map[string]dependency)

	for f := range allFunctions {
		ok, id := isDependency(f)
		if ok || dc.IncludeStdlib {
			//fmt.Println(f.Pkg.Pkg.Path())
			entry := dependencyMap[id]
			locs := calculateLocs(f)

			// is it reachable?
			_, isReachable := reachable[f]
			if isReachable {
				entry.reachableLocs += locs
			} else {
				entry.unreachableLocs += locs
			}
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

	sort.Slice(dependencyNames, func(i, j int) bool {
		return dependencyNames[i] < dependencyNames[j]
	})

	// output
	for _, dependencyName := range dependencyNames {
		entry := dependencyMap[dependencyName]
		total := entry.reachableLocs + entry.unreachableLocs
		percentage := (100.0 * float64(entry.reachableLocs)) / float64(total)
		if percentage < dc.UsageThreshold {
			state.Logger.Warnf("Dependency usage below %3.1f %%: %q %d %d (%3.1f %%)\n",
				dc.UsageThreshold, dependencyName, entry.reachableLocs, total, percentage)
		} else {
			state.Logger.Infof("%q %d %d\n", dependencyName, entry.reachableLocs, total)
		}
		if dc.CsvFile != nil {
			dc.CsvFile.Write([]byte(fmt.Sprintf("%s,%d,%d,%3.2f\n",
				dependencyName, entry.reachableLocs, total, percentage)))
		}
	}

	return dependencyGraph
}
