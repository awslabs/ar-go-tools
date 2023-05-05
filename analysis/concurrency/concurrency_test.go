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

package concurrency

import (
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/argot/analysis/testutils"
	. "github.com/awslabs/argot/internal/funcutil"
)

func loadConcurrencyTestResult(t *testing.T, subDir string) AnalysisResult {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/", subDir)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	program, cfg := testutils.LoadTest(t, ".", []string{})
	ar, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}
	// Remove reports - comment if you want to inspect
	os.RemoveAll(cfg.ReportsDir)
	return ar
}

func TestTrivial(t *testing.T) {
	ar := loadConcurrencyTestResult(t, "trivial")

	for goInstr, id := range ar.GoCalls {
		t.Logf("%d : %s @ %s", id, goInstr, ar.AnalyzerState.Program.Fset.Position(goInstr.Pos()))
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
