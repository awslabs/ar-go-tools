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

package concurrency_test

import (
	"embed"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/concurrency"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	. "github.com/awslabs/ar-go-tools/internal/funcutil"
)

//go:embed testdata
var testfsys embed.FS

func loadConcurrencyTestResult(t *testing.T, subDir string) (concurrency.AnalysisResult, *ptr.State) {
	// only works for "trivial" for now because that's the only dir that's embedded in testfsys
	dirName := filepath.Join("./testdata", subDir)
	lp, err := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	state, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to pointer state: %s", err)
	}
	ar, err := concurrency.Analyze(state)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}
	return ar, state
}

func TestTrivial(t *testing.T) {
	ar, state := loadConcurrencyTestResult(t, "trivial")

	for goInstr, id := range ar.GoCalls {
		t.Logf("%d : %s @ %s", id, goInstr, state.Program.Fset.Position(goInstr.Pos()))
	}

	res := make(map[string]string, len(ar.NodeColors))
	for node, color := range ar.NodeColors {

		e := strings.Join(Map(SetToOrderedSlice(color), func(i uint32) string { return strconv.Itoa(int(i)) }), ",")
		t.Logf("Node %s - %s", node.String(), e)

		if (node.Func.Name() == "main" || node.Func.Name() == "init") && (len(color) != 1 || !color[0]) {
			t.Fatalf("main should be top-level (color 0)")
		}

		res[node.Func.Name()] = e
	}
	if res["f1"] != res["f11"] {
		t.Fatalf("f1 and f11 should be in the same thread, but they have color %s and %s", res["f1"], res["f11"])
	}
	if !strings.Contains(res["f13"], res["f2"]) {
		t.Fatalf("f13 should be in f2's thread, but got f2:%s and f3:%s", res["f2"], res["f3"])
	}
}
