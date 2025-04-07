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

package structinit_test

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
	"github.com/awslabs/ar-go-tools/analysis/syntactic/structinit"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	resultMonad "github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

//go:embed testdata
var testfsys embed.FS

func TestIncompleteInits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		dirName string
	}{
		{
			name:    "field-val",
			dirName: "field-val",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lp, got := runAnalysis(t, tt.dirName)
			want := expectedIncompleteInits(lp)
			checkHasResults(t, got, want)
			checkInits(t, got, want)
		})
	}
}

func TestInvalidWriteAndBadReinits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		dirName string
	}{
		{
			name:    "field-val",
			dirName: "field-val",
		},
		{
			name:    "field-func",
			dirName: "field-func",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lp, got := runAnalysis(t, tt.dirName)
			checkInvalidWrites(t, got, expectedInvalidWrites(lp))
			checkBadReinit(t, got, expectedBadReinits(lp))
		})
	}
}

func runAnalysis(t *testing.T, dirName string) (*loadprogram.State, structinit.AnalysisResult) {
	dirName = filepath.Join("./testdata", dirName)
	lpState := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: false})
	lp, err := lpState.Value()
	if err != nil {
		t.Fatalf("failed to load test: %s", err)
	}
	setupConfig(lp)
	state, err := resultMonad.Bind(lpState, ptr.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load : %s", err)
	}
	result, err := structinit.Analyze(state, structinit.AnalysisReqs{})
	if err != nil {
		t.Fatalf("struct-init analysis failed: %v", err)
	}
	return lp, result
}

func checkInits(t *testing.T, res structinit.AnalysisResult, want map[string][]analysistest.LPos) {
	got := make(map[string][]analysistest.LPos)
	for structType, info := range res.InitInfos {
		name := structType.Obj().Name()
		for _, alloc := range info.IncompleteInits {
			gotPos := analysistest.NewLPos(alloc.Pos)
			got[name] = append(got[name], gotPos)
		}
	}

	compareGotWant(t, got, want, "incomplete inits")
}

func checkBadReinit(t *testing.T, res structinit.AnalysisResult, want map[string][]analysistest.LPos) {
	got := make(map[string][]analysistest.LPos)
	for structType, info := range res.InitInfos {
		name := structType.Obj().Name()
		for _, badReinit := range info.BadReinits {
			gotPos := analysistest.NewLPos(badReinit.Pos)
			got[name] = append(got[name], gotPos)
		}
	}

	// make sure got has all the structs and positions in want
	compareGotWant(t, got, want, "bad reinit")
}

func checkInvalidWrites(t *testing.T, res structinit.AnalysisResult, want map[string][]analysistest.LPos) {
	got := make(map[string][]analysistest.LPos)
	for structType, info := range res.InitInfos {
		name := structType.Obj().Name()
		for _, writes := range info.InvalidWrites {
			for _, write := range writes {
				gotPos := analysistest.NewLPos(write.Pos)
				got[name] = append(got[name], gotPos)
			}
		}
	}

	compareGotWant(t, got, want, "invalid write")
}

func checkHasResults(t *testing.T, res structinit.AnalysisResult, want map[string][]analysistest.LPos) {
	if len(res.InitInfos) == 0 {
		t.Fatalf("no analysis results")
	}
	if len(want) == 0 {
		t.Fatalf("no expected test results")
	}
}

func compareGotWant(t *testing.T, got map[string][]analysistest.LPos, want map[string][]analysistest.LPos, what string) {
	for wantName, wantPosns := range want {
		if _, ok := got[wantName]; !ok {
			t.Errorf("failed to find struct name in analysis results: %v", wantName)
			continue
		}

		for _, wantPos := range wantPosns {
			if !funcutil.Contains(got[wantName], wantPos) {
				t.Errorf("failed to find %s position for struct %v in analysis results: %v", what, wantName, wantPos)
			}
		}
	}

	// make sure want has all the structs and positions in got
	for gotName, gotPosns := range got {
		if _, ok := want[gotName]; !ok {
			t.Errorf("failed to find struct name in test annotations: %v", gotName)
			continue
		}

		for _, gotPos := range gotPosns {
			if !funcutil.Contains(want[gotName], gotPos) {
				t.Errorf("failed to find %s position for struct %v in test annotations: %v", what, gotName, gotPos)
			}
		}
	}

	if t.Failed() {
		t.Logf("want: %+v\n", want)
		t.Logf("got: %+v\n", got)
	}
}

func setupConfig(lp *loadprogram.State) {
	level := config.ErrLevel // change this as needed for debugging
	lp.Logger.Level = level

	lp.Config.Options.ReportCoverage = false
	lp.Config.Options.ReportsDir = ""
	lp.Config.LogLevel = int(level)
}

// incompleteInitRegex matches annotations of the form "@IncompleteInit(id1, id2, id3)"
var incompleteInitRegex = regexp.MustCompile(`//.*@IncompleteInit\(((?:\s*\w\s*,?)+)\)`)

// invalidWriteRegex matches annotations of the form "@InvalidWrite(id1, id2, id3)"
var invalidWriteRegex = regexp.MustCompile(`//.*@InvalidWrite\(((?:\s*\w\s*,?)+)\)`)

// invalidWriteRegex matches annotations of the form "@InvalidWrite(id1, id2, id3)"
var badReinitRegex = regexp.MustCompile(`//.*@BadReinit\(((?:\s*\w\s*,?)+)\)`)

// expectedIncompleteInits analyzes the files in astFiles and looks for comments
// @IncompleteInit(id1, id2, ...) to construct the expected positions of the incomplete
// initializations of a struct.
// Each id must be the name of the struct that is not completely initialized. There may be multiple.
// These positions are represented as a map from the struct name to all the
// incomplete initialization positions of that struct.
func expectedIncompleteInits(lp *loadprogram.State) map[string][]analysistest.LPos {
	return expectedAnnotations(incompleteInitRegex, lp)
}

// expectedInvalidWrites analyzes the files in astFiles and looks for comments
// @InvalidWrite(id1, id2, ...) to construct the expected positions of the invalid writes to
// a struct field.
// Each id must be the name of the struct whose field is written to. There may be
// multiple.
// These positions are represented as a map from the struct name to all the
// invalid write operations' positions.
func expectedInvalidWrites(lp *loadprogram.State) map[string][]analysistest.LPos {
	return expectedAnnotations(invalidWriteRegex, lp)
}

// expectedBadReinits analyzes the files in astFiles and looks for comments
// @BadReinit(id1, id2, ...) to construct the expected positions of the invalid writes to
// a struct field.
// Each id must be the name of the struct whose field is written to. There may be
// multiple.
// These positions are represented as a map from the struct name to all the
// invalid write operations' positions.
func expectedBadReinits(lp *loadprogram.State) map[string][]analysistest.LPos {
	return expectedAnnotations(badReinitRegex, lp)
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
