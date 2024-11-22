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

package rewrite_test

import (
	"embed"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

//go:embed testdata
var testFSys embed.FS

func TestWithInlining(t *testing.T) {
	dirName := filepath.Join("./testdata", "simple")
	lp := analysistest.LoadTest(testFSys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true})
	state, err := result.Bind(lp, ptr.NewState).Value()

	if err != nil {
		t.Fatalf("Failed to load state: %s", err)
	}
	for i, r := range state.ReachableFunctions() {
		if i.Name() == "main" && r {
			checkCalls(t, state, i, 2, []string{"main$1", "main$2"}, []string{"sort.Slice", "(*sync.Once).Do"})
		}
	}
}

func TestWithoutInlining(t *testing.T) {
	dirName := filepath.Join("./testdata", "simple")
	lp := analysistest.LoadTest(testFSys, dirName, []string{}, analysistest.LoadTestOptions{})
	state, err := result.Bind(lp, ptr.NewState).Value()
	if err != nil {
		t.Fatalf("Failed to load pointer state: %s", err)
	}
	for i, r := range state.ReachableFunctions() {
		if i.Name() == "main" && r {
			checkCalls(t, state, i, 2, []string{"sort.Slice", "(*sync.Once).Do"}, []string{"main$1", "main$2"})
		}
	}
}

func checkCalls(t *testing.T,
	state *ptr.State,
	i *ssa.Function,
	n int,
	expected []string,
	unexpected []string) {

	seen := map[string]bool{}

	for _, y := range expected {
		seen[y] = false
	}
	if state.PointerAnalysis.CallGraph == nil || state.PointerAnalysis.CallGraph.Nodes == nil {
		state.Logger.Errorf("missing information in pointer analysis")
		return
	}
	ithNode := state.PointerAnalysis.CallGraph.Nodes[i]
	if ithNode == nil {
		return
	}

	if n0 := len(ithNode.Out); n0 < n {
		t.Fatalf("Expected more than %d calls, got %d", n, n0)
	}

	for _, d := range ithNode.Out {
		for _, x := range unexpected {
			if strings.Contains(d.String(), x) {
				t.Fatalf("Incorrect call to %s", x)
			}
		}
		for _, y := range expected {
			seen[y] = seen[y] || strings.Contains(d.String(), y)
		}

	}

	for _, y := range expected {
		if !seen[y] {
			t.Fatalf("Missing call to %s.", y)
		}
	}
}
