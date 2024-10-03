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

package graphutil_test

import (
	"embed"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/graphutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"github.com/yourbasic/graph"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

//go:embed testdata
var testfsys embed.FS

func TestFindAllElementaryCycles(t *testing.T) {
	dir := filepath.Join("testdata", "trivial")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true})
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	program := lp.Prog

	pCfg := &pointer.Config{
		Mains:           ssautil.MainPackages(program.AllPackages()),
		Reflection:      false,
		BuildCallGraph:  true,
		Queries:         make(map[ssa.Value]struct{}),
		IndirectQueries: make(map[ssa.Value]struct{}),
	}

	// Do the pointer analysis
	pointerAnalysis, err := pointer.Analyze(pCfg)

	if err != nil {
		t.Errorf("Error in pointer analysis: %s", err)
	}

	cg := pointerAnalysis.CallGraph
	iterator := graphutil.NewCallgraphIterator(cg)
	stats := graph.Check(iterator)
	t.Logf("Stats:\n\tsize: %d\n\tmulti: %d\n\tloops: %d\n\tisolated: %d",
		stats.Size, stats.Multi, stats.Loops, stats.Isolated)

	cycles := graphutil.FindAllElementaryCycles(iterator)
	expected := []string{"242", "25102", "2642", "383", "3983"}

	n := len(cycles)
	if n != 5 {
		t.Fatalf("Expected 5 elementary cycles, found %d", n)
	} else {
		results := make([]string, n)
		for i, cycle := range cycles {
			results[i] = strings.Join(
				funcutil.Map(cycle, func(_x int64) string { return strconv.Itoa(int(_x)) }),
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
