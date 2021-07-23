// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/tools/go/ssa"
)

func ssaStatistics(allFunctions *map[*ssa.Function]bool, exclude []string, jsonFlag bool) {

	type Result struct {
		NumberOfFunctions         uint
		NumberOfNonemptyFunctions uint
		NumberOfBlocks            uint
		NumberOfInstructions      uint
	}

	result := Result{0, 0, 0, 0}

	for f := range *allFunctions {
		result.NumberOfFunctions++

		if len(f.Blocks) != 0 {
			result.NumberOfNonemptyFunctions++
			for _, b := range f.Blocks {
				result.NumberOfBlocks++
				result.NumberOfInstructions += uint(len(b.Instrs))
			}
		}
	}

	if jsonFlag {
		buf, _ := json.Marshal(result)
		fmt.Println(string(buf))
	} else {
		fmt.Printf("Number of functions: %d\n", result.NumberOfFunctions)
		fmt.Printf("Number of nonempty functions: %d\n", result.NumberOfNonemptyFunctions)
		fmt.Printf("Number of blocks: %d\n", result.NumberOfBlocks)
		fmt.Printf("Number of instructions: %d\n", result.NumberOfInstructions)
	}
}
