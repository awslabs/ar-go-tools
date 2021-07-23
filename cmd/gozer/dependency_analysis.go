// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	//	"encoding/json"
	"fmt"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"sort"
	"strings"
)

func isDependency(f *ssa.Function) (bool, string) {
	if f.Pkg != nil {
		packagePath := f.Pkg.Pkg.Path()
		split := strings.Split(packagePath, "/")
		if len(split) >= 3 {
			if strings.Index(split[0], ".") == -1 {
				// no dot in the first component, e.g., "runtime"
				return false, ""
			} else {
				// dot found, e.g. github.com
				return true, split[0] + "/" + split[1] + "/" + split[2]
			}
		} else {
			return false, ""
		}
	} else {
		return false, ""
	}
}

func isRuntime(f *ssa.Function) bool {
	return false
}

func findEntry(allFunctions map[*ssa.Function]bool) *ssa.Function {
	for f, _ := range allFunctions {
		if f.RelString(nil) == "command-line-arguments.main" {
			return f
		}
	}

	return nil
}

func findReachable(allFunctions map[*ssa.Function]bool) map[*ssa.Function]bool {
	reachable := make(map[*ssa.Function]bool)

	frontier := make([]*ssa.Function, 0)

	entry := findEntry(allFunctions)
	if entry != nil {
		frontier = append(frontier, entry)
	}

	for len(frontier) != 0 {
		f := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		reachable[f] = true

		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				switch v := instr.(type) {
				case *ssa.Call:
					// invoke?
					if v.Call.IsInvoke() {
					} else {
						switch value := v.Call.Value.(type) {
						case *ssa.Function:
							_, ok := reachable[value]
							if !ok {
								frontier = append(frontier, value)
							}

						case *ssa.MakeClosure:
							switch fn := value.Fn.(type) {
							case *ssa.Function:
								_, ok := reachable[fn]
								if !ok {
									frontier = append(frontier, fn)
								}
							}
						}
					}

				case *ssa.MakeInterface:
					// we consider all methods of this type
				}
			}
		}

	}

	return reachable
}

func calculateLocs(f *ssa.Function) uint {

	var numberOfInstructions uint = 0

	for _, b := range f.Blocks {
		numberOfInstructions += uint(len(b.Instrs))
	}

	return numberOfInstructions
}

func reachableFunctionsAnalysis(program *ssa.Program, jsonFlag bool) {

	allFunctions := ssautil.AllFunctions(program)
	reachable := findReachable(allFunctions)

	functionNames := make([]string, 0, len(reachable))

	for f, _ := range reachable {
		functionNames = append(functionNames, f.RelString(nil))
	}

	// sort alphabetically by name
	sort.Slice(functionNames, func(i, j int) bool {
		return functionNames[i] < functionNames[j]
	})

	for _, name := range functionNames {
		fmt.Printf("%s\n", name)
	}
}

func dependencyAnalysis(program *ssa.Program, jsonFlag bool) {

	allFunctions := ssautil.AllFunctions(program)

	// functions known to be reachable
	reachable := findReachable(allFunctions)

	// count reachable and unreachable LOCs, per dependency
	type dependency struct {
		reachableLocs   uint
		unreachableLocs uint
	}

	dependencyMap := make(map[string]dependency)

	for f, _ := range allFunctions {
		ok, id := isDependency(f)
		if ok {
			entry := dependencyMap[id]
			locs := calculateLocs(f)

			// is it reachable?
			_, ok := reachable[f]
			if ok {
				entry.reachableLocs += locs
			} else {
				entry.unreachableLocs += locs
			}

			dependencyMap[id] = entry
		}
	}

	// order alphabetically
	dependencyNames := make([]string, 0, len(dependencyMap))

	for key, _ := range dependencyMap {
		dependencyNames = append(dependencyNames, key)
	}

	sort.Slice(dependencyNames, func(i, j int) bool {
		return dependencyNames[i] < dependencyNames[j]
	})

	// output
	for _, dependencyName := range dependencyNames {
		entry := dependencyMap[dependencyName]
		total := entry.reachableLocs + entry.unreachableLocs
		// fmt.Printf("%s %d%%\n", dependencyName, 100 * entry.reachableLocs / total)
		fmt.Printf("%s %d %d\n", dependencyName, entry.reachableLocs, total)
	}
}
