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

package graph_ops

import (
	"log"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/functional"
	"github.com/awslabs/argot/analysis/utils"
	"github.com/yourbasic/graph"
	"golang.org/x/exp/slices"
)

func TestFindAllElementaryCycles(t *testing.T) {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/graph-ops/trivial")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	program, config := utils.LoadTest(t, ".", []string{})

	cache, err := dataflow.BuildFullCache(log.New(os.Stdout, "[TEST] ", log.Flags()), config, program)

	if err != nil {
		t.Errorf("Error building cache: %s", err)
	}

	cg := cache.PointerAnalysis.CallGraph
	iterator := NewCallgraphIterator(cg)
	stats := graph.Check(iterator)
	t.Logf("Stats:\n\tsize: %d\n\tmulti: %d\n\tloops: %d\n\tisolated: %d",
		stats.Size, stats.Multi, stats.Loops, stats.Isolated)

	cycles := FindAllElementaryCycles(iterator)
	expected := []string{"242", "25102", "2642", "383", "3983"}

	n := len(cycles)
	if n != 5 {
		t.Fatalf("Expected 5 elementary cycles, found %d", n)
	} else {
		results := make([]string, n)
		for i, cycle := range cycles {
			results[i] = strings.Join(
				functional.Map(cycle, func(_x int64) string { return strconv.Itoa(int(_x)) }),
				"")
		}
		sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
		if !slices.Equal(results, expected) {
			t.Logf("Cycles:")
			for i, s := range results {
				t.Logf("Cycle %d: %s", i, s)
			}
			t.Fatalf("Cycles not as expected")
		}
	}
}
