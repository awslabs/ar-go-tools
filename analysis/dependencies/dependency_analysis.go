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
func computePath(filepath string, pkg string) string {

	verbose := strings.HasSuffix(filepath, "agent.go")
	if verbose {
		fmt.Printf("computePath(%q,%q)=", filepath, pkg)
	}
	// if the full package name appears in the filepath, then just chop off the prefix
	// and return the full packagename with the path within the package.
	offset := strings.Index(filepath, pkg)
	if offset >= 0 {
		if verbose {
			fmt.Println("1", filepath[offset:])
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
				fmt.Println(filepath)
			}
			return filepath // bail
		}
		split = split + newsplit
		offset = strings.Index(filepath, pkg[split:])
		if offset >= 0 {
			if verbose {
				fmt.Println(pkg[:split] + filepath[offset:])
			}
			return pkg[:split] + filepath[offset:]
		}
		split++ // skip the "/"
	}
}

func emitCoverageLine(file io.Writer, program *ssa.Program, f *ssa.Function, name string, reachable bool, locs uint) {
	syn := f.Syntax()
	if syn == nil {
		return
	}

	start := program.Fset.Position(syn.Pos())
	end := program.Fset.Position(syn.End())

	newname := computePath(start.Filename, f.Package().Pkg.Path())

	reachval := 0
	if reachable {
		reachval = 1
	}

	str := fmt.Sprintf("%s:%d.%d,%d.%d %d %d\n", newname, start.Line, start.Column,
		end.Line, end.Column, locs, reachval)

	file.Write([]byte(str[:]))

}

// DependencyAnalysis runs the dependency analysis on all the functions in the ssa.Program
// Writes a coverage file in covFile indicating which functions are reachable.
func DependencyAnalysis(program *ssa.Program, jsonFlag bool, includeStdlib bool, covFile io.Writer, graph bool) reachability.DependencyGraph {

	// all functions we have got
	allFunctions := ssautil.AllFunctions(program)

	var dependencyGraph reachability.DependencyGraph = nil
	if graph {
		dependencyGraph = reachability.NewDependencyGraph()
	}

	// functions known to be reachable
	reachable := reachability.FindReachable(program, false, false, dependencyGraph)

	// count reachable and unreachable LOCs, per dependency
	type dependency struct {
		reachableLocs   uint
		unreachableLocs uint
	}

	dependencyMap := make(map[string]dependency)

	for f := range allFunctions {
		ok, id := isDependency(f)
		if ok || includeStdlib {
			//fmt.Println(f.Pkg.Pkg.Path())
			entry := dependencyMap[id]
			locs := calculateLocs(f)

			// is it reachable?
			_, ok := reachable[f]
			if ok {
				entry.reachableLocs += locs
			} else {
				entry.unreachableLocs += locs
			}
			if covFile != nil {
				emitCoverageLine(covFile, program, f, id, ok, locs)
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
		fmt.Printf("%q %d %d\n", dependencyName, entry.reachableLocs, total)
	}

	return dependencyGraph
}
