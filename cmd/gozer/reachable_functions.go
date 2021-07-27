// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	//	"encoding/json"
	"fmt"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"sort"
)

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
