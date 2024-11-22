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
	"log"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// Result contains the simple statistics returned by running the SSAStatistics function
type Result struct {
	NumberOfFunctions         uint
	NumberOfNonemptyFunctions uint
	NumberOfBlocks            uint
	NumberOfInstructions      uint
}

// SSAStatistics returns a Result with general statistics about the SSA representation of the functions.
// The exclude parameter is currently ignored.
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

// DeferStat is a statistic for a single function
type DeferStat struct {
	NumDefers    int
	NumRunDefers int
}

// DeferStatsResult holds the information gathered by DeferStats on defers
type DeferStatsResult struct {
	NumFunctionsWithDefers  int
	NumDefers               int
	NumRunDefers            int
	FunctionsWithManyDefers map[string]DeferStat
}

// DeferStats logs information about the number of defers in each functions in the map
func DeferStats(functions *map[*ssa.Function]bool) DeferStatsResult {
	num := 0
	sumDefers := 0
	sumRunDefers := 0
	functionsWithManyDefers := map[string]DeferStat{}
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
			functionsWithManyDefers[lang.PackageNameFromFunction(f)+"."+f.Name()] = DeferStat{defers, rundefers}
		}
		sumDefers += defers
		if defers > 0 {
			num++
			sumRunDefers += rundefers
		}
	}
	return DeferStatsResult{
		NumFunctionsWithDefers:  num,
		NumDefers:               sumDefers,
		NumRunDefers:            sumRunDefers,
		FunctionsWithManyDefers: functionsWithManyDefers,
	}
}

// ClosureLocationsStats logs information about the number of closures in each function in the map, focusing on those functions
// whose package name starts with interestPrefix
func ClosureLocationsStats(log *log.Logger, functions *map[*ssa.Function]bool, withPkgPrefix string) {
	num := 0

	for f := range *functions {
		found := false
		pkg := lang.PackageNameFromFunction(f)
		if !ofInterest(pkg, false, withPkgPrefix) {
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

					log.Printf("\n%s %s\n", pkg+"."+f.Name(), c.String())
					target := c.Fn.(*ssa.Function)
					log.Printf("\tBlocks=%d\n\tLocals=%d\n\tParams=%d\n\tFreeVars=%d\n",
						len(target.Blocks), len(target.Locals), len(target.Params), len(target.FreeVars))
					if len(target.FreeVars) > 0 {
						for i, v := range target.FreeVars {
							log.Printf("\tFreevar[%d] = %s\n", i, v.Name())
						}
					}
					log.Println("parent=", target.Parent())
					if target.Recover != nil {
						log.Println("\tRECOVER")
					}
					if typ != "" {
						log.Println("Type = ", typ)
					}
					found = true
				}
			}
		}
		if found {
			num++
		}
	}

	log.Printf("%d functions had closures\n", num)

}

func ofInterest(name string, include3P bool, interestPrefix string) bool {
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

	if !include3P && !strings.HasPrefix(name, interestPrefix) {
		return false
	}

	return true
}

// ClosureUsageStatistics is a simple record that contains information about usage of closures in a program
type ClosureUsageStatistics struct {
	// AnonsCapturingChannels is the set of anonymous functions capturing channels
	AnonsCapturingChannels map[*ssa.Function]bool
	// TotalAnonCalls is the total number of anonymous functions called
	TotalAnonCalls int
	// TotalAnonFunctions is the total number of anonymous functions defined
	TotalAnonFunctions int
	// TotalMakeClosures is the total number of closure creations
	TotalMakeClosures int
	// ClosuresCalled maps call instructions to the instruction where the closure is created
	ClosuresCalled map[ssa.CallInstruction]ssa.Instruction
	// ClosuresImmediatelyCalled is the set of instructions where a closure is immediately called
	ClosuresImmediatelyCalled map[ssa.Instruction]bool
	// ClosuresNoClass is the set of closures that have not been classified in ClosuresImmediatelyCalled,
	// ClosuresPassedAsArgs or ClosuresReturned
	ClosuresNoClass map[ssa.Instruction]bool
	// ClosuresPassedAsArgs is the set of call instructions where a closure is passed as an argument
	ClosuresPassedAsArgs map[ssa.CallInstruction]ssa.Instruction
	// ClosuresReturned is the set of instructions where a closure is being returned by a function
	ClosuresReturned map[ssa.Instruction]bool
}

// ComputeClosureUsageStats computes statistics about the usage of closures in the program contained in the state. This
// requires the pointer analysis to have been computed in the state.
func ComputeClosureUsageStats(state *dataflow.State) (ClosureUsageStatistics, error) {
	if state.PointerAnalysis == nil || state.Program == nil || state.FlowGraph == nil {
		return ClosureUsageStatistics{}, fmt.Errorf("state should be built to collect stats")
	}
	stats := &ClosureUsageStatistics{
		AnonsCapturingChannels:    map[*ssa.Function]bool{},
		ClosuresImmediatelyCalled: map[ssa.Instruction]bool{},
		ClosuresReturned:          map[ssa.Instruction]bool{},
		ClosuresNoClass:           map[ssa.Instruction]bool{},
		ClosuresPassedAsArgs:      map[ssa.CallInstruction]ssa.Instruction{},
		ClosuresCalled:            map[ssa.CallInstruction]ssa.Instruction{},
	}
	for function := range state.ReachableFunctions() {
		stats.doFunction(state, function)
	}
	return *stats, nil
}

func (s *ClosureUsageStatistics) doFunction(state *dataflow.State, function *ssa.Function) {
	lang.IterateInstructions(function, s.doInstruction)

	if function.Parent() == nil { // not an anonymous function
		return
	}

	s.TotalAnonFunctions++
	if node := state.PointerAnalysis.CallGraph.Nodes[function]; node != nil {
		s.TotalAnonCalls += len(node.In)
	}

	for _, fv := range function.FreeVars {
		if lang.IsChannelEnclosingType(fv.Type()) {
			s.AnonsCapturingChannels[function] = true
		}
	}
	summary := state.FlowGraph.Summaries[function]
	if summary == nil {
		return
	}
}

func (s *ClosureUsageStatistics) doInstruction(index int, i ssa.Instruction) {
	if makeClosure, isMakeClosure := i.(*ssa.MakeClosure); isMakeClosure {
		classified := false
		s.TotalMakeClosures++
		// Is that closure immediately called in a go, defer or call?
		block := i.Block()
		if block != nil {
			if index+1 < len(block.Instrs) {
				switch i2 := block.Instrs[index+1].(type) {
				case ssa.CallInstruction:
					if i2.Common().Value == i.(ssa.Value) {
						s.ClosuresImmediatelyCalled[i2] = true
						classified = true
					}
				}
			}
		}
		// Is that closure passed as argument to another function call?
		for _, referrer := range *(makeClosure.Referrers()) {
			switch call := referrer.(type) {
			case ssa.CallInstruction:
				// The closure may be passed as an argument to the call
				for _, arg := range call.Common().Args {
					if arg == makeClosure {
						s.ClosuresPassedAsArgs[call] = makeClosure
						classified = true
					}
				}
				// the closure may be called here
				if call.Common().Value == makeClosure {
					s.ClosuresCalled[call] = makeClosure
				}
			case *ssa.Return:
				s.ClosuresReturned[makeClosure] = true
				classified = true
			}
		}
		if !classified {
			s.ClosuresNoClass[makeClosure] = true
		}
	}
}
