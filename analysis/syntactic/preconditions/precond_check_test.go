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

package preconditions

import (
	"embed"
	"go/ast"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	. "github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

//go:embed testdata
var testfsys embed.FS

func TestFuncCond(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		dirName string
	}{
		{
			name:    "func-cond",
			dirName: "func-cond",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _ = runAnalysis(t, tt.dirName)
		})
	}
}

func runAnalysis(t *testing.T, dirName string) (*loadprogram.State, AnalysisResult) {
	dirName = filepath.Join("./testdata", dirName)
	lpState := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: false})
	lp, err := lpState.Value()
	if err != nil {
		t.Fatalf("failedo load test: %s", err)
	}
	setupConfig(lp.Config)
	state, err := result.Bind(lpState, ptr.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load : %s", err)
	}
	analysisResult, err := Analyze(state, AnalysisReqs{})
	if err != nil {
		t.Fatalf("struct-init analysis failed: %v", err)
	}
	checkInvalidCalls(t, analysisResult, expectedInvalidCalls(lp))
	return lp, analysisResult
}

func setupConfig(cfg *config.Config) {
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(config.ErrLevel) // change this as needed for debugging
}

func checkInvalidCalls(t *testing.T, res AnalysisResult, want map[string][]analysistest.LPos) {

	if len(want) == 0 {
		t.Fatalf("no expected test results")
	}

	got := make(map[string][]analysistest.LPos)
	for tag, locs := range res.UncheckedLocs {
		for _, loc := range locs {
			gotPos := analysistest.NewLPos(loc)
			got[tag] = append(got[tag], gotPos)
		}
	}

	// make sure got has all the structs and positions in want
	for wantName, wantPosns := range want {
		if _, ok := got[wantName]; !ok {
			t.Errorf("failed to tag in analysis results: %v", wantName)
			continue
		}

		for _, wantPos := range wantPosns {
			if !Contains(got[wantName], wantPos) {
				t.Errorf("failed to find invalid call for tag %v in analysis results: %v", wantName, wantPos)
			}
		}
	}

	// make sure want has all the structs and positions in got
	for gotName, gotPosns := range got {
		if _, ok := want[gotName]; !ok {
			t.Errorf("failed to find tag in test annotations: %v", gotName)
			continue
		}

		for _, gotPos := range gotPosns {
			if !Contains(want[gotName], gotPos) {
				t.Errorf("failed to find invalid call location for tag %v in test annotations: %v", gotName, gotPos)
			}
		}
	}

	if t.Failed() {
		t.Logf("want: %+v\n", want)
		t.Logf("got: %+v\n", got)
	}
}

// invalidCallRegex matches annotations of the form "@InvalidCall(id1, id2, id3)"
var invalidCallRegex = regexp.MustCompile(`//.*@InvalidCall\(((?:\s*\w\s*,?)+)\)`)

// expectedInvalidCalls analyzes the files in astFiles and looks for comments
// @InvalidCalls(id1, id2, ...) to construct the expected positions of the invalid calls for a tagged problem.
// These positions are represented as a map from the problem tag to all the invalid calls of the function in that
// problem.
func expectedInvalidCalls(lp *loadprogram.State) map[string][]analysistest.LPos {
	return expectedAnnotations(invalidCallRegex, lp)
}

func expectedAnnotations(regex *regexp.Regexp, lp *loadprogram.State) map[string][]analysistest.LPos {
	astFiles := analysistest.AstFiles(lp.Packages)
	fset := lp.Program.Fset
	res := make(map[string][]analysistest.LPos)

	analysistest.MapComments(astFiles, func(c *ast.Comment) {
		pos := fset.Position(c.Pos())
		if m := regex.FindStringSubmatch(c.Text); len(m) > 1 {
			for _, ident := range strings.Split(m[1], ",") {
				ident := strings.TrimSpace(ident)
				res[ident] = append(res[ident], analysistest.NewLPos(pos))
			}
		}
	})

	return res
}
