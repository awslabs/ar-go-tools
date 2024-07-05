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

package defers

import (
	"os"
	"path"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// This loadProgram function is needed due to a circular import in the analysis <-> defers packages
// We can't use analysis.LoadProgram
func loadProgram(file string) (*ssa.Program, error) {
	cfg := loader.Config{}
	cfg.CreateFromFilenames("main", file)
	prog, err := cfg.Load()
	if err != nil {
		return nil, err
	}
	//goland:noinspection ALL
	program := ssautil.CreateProgram(prog, 0)
	program.Build()
	return program, err
}

// Test that the functions in defer/basic.go compute the given set(s) of defers
func TestBasic(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "testdata/src/defer/")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
	program, _ := loadProgram("basic.go")
	for f := range ssautil.AllFunctions(program) {
		results := AnalyzeFunction(f, config.NewLogGroup(config.NewDefault()))
		switch f.Name() {
		case "f1":
			assertBoundedness(t, f, results, true)
			assertStackSizes(t, f, results, []int{1})
		case "f2":
			assertBoundedness(t, f, results, true)
			assertStackSizes(t, f, results, []int{0, 1})
		case "f3":
			assertBoundedness(t, f, results, true)
			assertStackSizes(t, f, results, []int{2})
		case "f4":
			assertBoundedness(t, f, results, true)
			assertStackSizes(t, f, results, []int{0, 1, 1})
		case "f5":
			assertBoundedness(t, f, results, false)
			assertStackSizes(t, f, results, []int{0, 1})
		case "f6":
			assertBoundedness(t, f, results, true)
			assertStackSizes(t, f, results, []int{0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4})
		case "f7":
			assertBoundedness(t, f, results, true)
			assertStackSizes(t, f, results, []int{1, 2})
		}
	}
}

// Check that the boundness flag is as expected
func assertBoundedness(t *testing.T, f *ssa.Function, results Results, shouldBeBounded bool) {
	if results.DeferStackBounded != shouldBeBounded {
		t.Fatalf("Stack boundedness != %v in %v", shouldBeBounded, f.Name())
	}
}

// Check that the set of sizes of stacks is what is expected. This combines all the sets of stacks from
// all return points into one big bag, and then checks that the multiset is the same as what is expected
// If there is one return before any defers, and then another after one defer, expect {0, 1}
// If there are two unconditional defers and then a single return, the expected multiset is {2}
func assertStackSizes(t *testing.T, f *ssa.Function, results Results, expectedSizes []int) {
	actualSizes := []int{}
	for _, setOfStacks := range results.RunDeferSets {
		for _, stack := range setOfStacks {
			actualSizes = append(actualSizes, len(stack))
		}
	}
	// Compare multisets by sorting and then checking the sequences are the same
	sort.Ints(actualSizes)
	if !reflect.DeepEqual(actualSizes, expectedSizes) {
		t.Fatalf("Unexpected stack sizes in %v, expected: %v vs computed: %v\n", f.Name(), expectedSizes, actualSizes)
	}
}
