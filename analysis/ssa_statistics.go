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
	"strings"

	"github.com/awslabs/argot/analysis/ssafuncs"
	"golang.org/x/tools/go/ssa"
)

type Result struct {
	NumberOfFunctions         uint
	NumberOfNonemptyFunctions uint
	NumberOfBlocks            uint
	NumberOfInstructions      uint
}

func SSAStatistics(functions *map[*ssa.Function]bool, exclude []string) Result {

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

	return result
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
			fmt.Printf("%s has %d defers and %d rundefers\n", ssafuncs.PackageNameFromFunction(f)+"."+f.Name(), defers, rundefers)
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
		pkg := ssafuncs.PackageNameFromFunction(f)
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
