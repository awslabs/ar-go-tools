// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package analysis

import (
	"encoding/json"
	"fmt"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/packagescan"
	"golang.org/x/tools/go/ssa"
)

func SSAStatistics(functions *map[*ssa.Function]bool, exclude []string, jsonFlag bool) {

	type Result struct {
		NumberOfFunctions         uint
		NumberOfNonemptyFunctions uint
		NumberOfBlocks            uint
		NumberOfInstructions      uint
	}

	result := Result{0, 0, 0, 0}

	for f := range *functions {
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

func DeferStats(functions *map[*ssa.Function]bool) {
	num := 0
	sumDefers := 0
	sumRunDefers := 0
	for f := range *functions {
		defers := 0
		rundefers := 0

		for _, b := range f.Blocks {
			for _, i := range b.Instrs {
				if _, ok := i.(*ssa.Defer); ok {
					defers++
				}
				if _, ok := i.(*ssa.RunDefers); ok {
					rundefers++
				}
			}
		}
		if defers > 1 {
			fmt.Printf("%s has %d defers and %d rundefers\n", packagescan.PackageNameFromFunction(f)+"."+f.Name(), defers, rundefers)
		}
		sumDefers += defers
		if defers > 0 {
			num++
			sumRunDefers += rundefers
		}
	}
	fmt.Printf("%d functions had defers\n", num)
	fmt.Printf("%d total defers (%f/func)\n", sumDefers, float32(sumDefers)/float32(num))
	fmt.Printf("%d total rundefers (%f/func)\n", sumRunDefers, float32(sumRunDefers)/float32(num))

}

func ClosureStats(functions *map[*ssa.Function]bool) {
	num := 0

	for f := range *functions {
		found := false
		pkg := packagescan.PackageNameFromFunction(f)
		if !ofInterest(pkg, false) {
			continue
		}
		for _, b := range f.Blocks {
			typ := ""
			for _, i := range b.Instrs {
				if _, ok := i.(*ssa.Go); ok {
					typ = "GOROUTINE"
				}
				if _, ok := i.(*ssa.Defer); ok {
					typ = "DEFER"
				}
				if c, ok := i.(*ssa.MakeClosure); ok {

					fmt.Printf("\n%s %s\n", pkg+"."+f.Name(), c.String())
					target := c.Fn.(*ssa.Function)
					fmt.Printf("\tBlocks=%d\n\tLocals=%d\n\tParams=%d\n\tFreeVars=%d\n",
						len(target.Blocks), len(target.Locals), len(target.Params), len(target.FreeVars))
					if len(target.FreeVars) > 0 {
						for i, v := range target.FreeVars {
							fmt.Printf("\tFreevar[%d] = %s\n", i, v.Name())
						}
					}
					//					for i, bind := range c.Bindings {
					//						fmt.Printf("\tbinding[%d]=%s\n", i, bind.Name())
					//					}
					fmt.Println("parent=", target.Parent())
					if target.Recover != nil {
						fmt.Println("\tRECOVER")
					}
					if typ != "" {
						fmt.Println("Type = ", typ)
					}
					found = true
				}
			}
		}
		if found {
			num++
		}
	}

	fmt.Printf("%d functions had closures\n", num)

}

func ofInterest(name string, include3P bool) bool {
	if !strings.Contains(name, "/") {
		return false
	}

	root := name[:strings.Index(name, "/")]

	if !strings.Contains(root, ".") {
		return false
	}

	if root == "golang.org" {
		return false
	}

	if !include3P && !strings.HasPrefix(name, "github.com/aws/amazon-ssm-agent") {
		return false
	}

	return true
}
