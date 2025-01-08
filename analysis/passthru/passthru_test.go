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

package passthru_test

import (
	"embed"
	"go/ast"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/passthru"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

//go:embed testdata
var testfsys embed.FS

func TestAnalyze(t *testing.T) {
	dirName := filepath.Join("./testdata", "basic")
	lpState := analysistest.LoadTest(testfsys, dirName, []string{},
		analysistest.LoadTestOptions{ApplyRewrite: false})
	lp, err := lpState.Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	setupConfig(lp)
	state, err := result.Bind(result.Bind(lpState, ptr.NewState), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load dataflow state: %v", err)
	}

	want := wantInvalidAccesses(lp)
	got, err := passthru.Analyze(state)
	if err != nil {
		t.Fatalf("passthru analysis failed: %v", err)
	}

	if len(got.InvalidAccesses) == 0 {
		t.Fatal("failed to detect any invalid accesses")
	}

	checkInvalidAccesses(t, state.Program, want, got)
	if t.Failed() {
		debugResult(t, want, got)
	}
}

func setupConfig(lp *loadprogram.State) {
	lp.Config.Options.ReportCoverage = false
	lp.Config.Options.ReportsDir = ""
	lp.Config.LogLevel = int(config.ErrLevel) // change this as needed for debugging

	lp.Logger = config.NewLogGroup(lp.Config)
}

// coreAllocRegex matches annotations of the form "@CoreAlloc(id1, id2, id3)"
var coreAllocRegex = regexp.MustCompile(`//.*@CoreAlloc\(((?:\s*\w\s*,?)+)\)`)

// invalidAccessRegex matches annotations of the form "@InvalidAccess(id1, id2, id3)"
var invalidAccessRegex = regexp.MustCompile(`//.*@InvalidAccess\(((?:\s*\w\s*,?)+)\)`)

// escapeRegex matches annotations of the form "@Escape(id1, id2, id3)"
var escapeRegex = regexp.MustCompile(`//.*@Escape\(((?:\s*\w\s*,?)+)\)`)

// wantInvalidAccesses analyzes the files in lp and looks for comments
// @InvalidAccess(id1, id2, ...) to construct the expected positions of the
// invalid accessses.
// These positions are represented as a map from the invalid access matching the
// id to all the core allocation ids.
func wantInvalidAccesses(lp *loadprogram.State) analysistest.TargetToSources {
	return wantTargetToSources(lp, coreAllocRegex, invalidAccessRegex)
}

// wantTargetToSources analyzes the files in lp and looks for comments
// matching sourceRegex and targetRegex to construct expected matches from
// targets to sources in the form of a map of target positions to all the source
// positions that reach that target.
func wantTargetToSources(lp *loadprogram.State, sourceRegex *regexp.Regexp, targetRegex *regexp.Regexp) analysistest.TargetToSources {
	astFiles := analysistest.AstFiles(lp.Packages)
	fset := lp.Program.Fset
	target2sources := make(analysistest.TargetToSources)
	sourceIDToSourcePos := map[string]analysistest.LPos{}

	// Get all the source positions with their identifiers
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		// Match a "@CoreAlloc(id1, id2, id3)"
		a := sourceRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			pos := fset.Position(c1.Pos())
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				sourceIDToSourcePos[sourceIdent] = analysistest.NewLPos(pos)
			}
		}
	})

	// Get all the target positions
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		// Match a "@InvalidAccess(id1, id2, id3)"
		a := targetRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			sourcePos := fset.Position(c1.Pos())
			for _, ident := range strings.Split(a[1], ",") {
				targetIdent := strings.TrimSpace(ident)
				targetPos, ok := sourceIDToSourcePos[targetIdent]
				if !ok {
					continue
				}
				targetId := analysistest.AnnotationID{ID: targetIdent, Meta: "", Pos: targetPos}
				if _, ok := target2sources[targetId]; !ok {
					target2sources[targetId] = make(map[analysistest.AnnotationID]bool)
				}
				// source's id is the same as targetIdent in this branch
				sourceId := analysistest.AnnotationID{
					ID:   targetIdent,
					Meta: "",
					Pos:  analysistest.NewLPos(sourcePos),
				}
				target2sources[targetId][sourceId] = true
			}
		}
	})

	return target2sources
}

// TODO refactor to remove duplicate code

// checkWrites checks that got's writes matches the wanted
// CoreAlloc->InvalidAccess annotation ids from the test.
func checkInvalidAccesses(t *testing.T, prog *ssa.Program, want analysistest.TargetToSources, got passthru.AnalysisResult) {
	// debugResult(t, want, got)

	type seenAlloc struct {
		Pos analysistest.LPos
	}
	type seenAccess struct {
		Pos analysistest.LPos
	}
	seenAccessOfAlloc := make(map[seenAlloc]map[seenAccess]bool)

	for _, gotAccess := range got.InvalidAccesses {
		accessPos := gotAccess.Pos
		if !accessPos.IsValid() {
			t.Errorf("invalid access position for: %v", gotAccess)
			continue
		}
		gotAccessPos := seenAccess{Pos: analysistest.RemoveColumn(accessPos)}

		for _, gotAlloc := range gotAccess.EscapedAllocs {
			allocPos := gotAlloc.Pos
			if !allocPos.IsValid() {
				t.Errorf("invalid position for: %v", gotAlloc)
				continue
			}
			gotAllocPos := seenAlloc{Pos: analysistest.RemoveColumn(allocPos)}
			if _, ok := seenAccessOfAlloc[gotAllocPos]; !ok {
				seenAccessOfAlloc[gotAllocPos] = make(map[seenAccess]bool)
			}

			seen := false
			for wantAllocID, wantAccessIDs := range want {
				if gotAllocPos.Pos == wantAllocID.Pos {
					for wantSourceID := range wantAccessIDs {
						if gotAccessPos.Pos == wantSourceID.Pos {
							seenAccessOfAlloc[gotAllocPos][gotAccessPos] = true
							seen = true
						}
					}
				}
			}
			if !seen {
				t.Errorf("false positive: %v -> %v", gotAlloc, gotAccess)
			}
		}
	}

	for wantTargetID, wantSourceIDs := range want {
		sTarget := seenAlloc{Pos: wantTargetID.Pos}
		for wantSourceID := range wantSourceIDs {
			sSource := seenAccess{Pos: wantSourceID.Pos}
			if !seenAccessOfAlloc[sTarget][sSource] {
				// Remaining entries have not been detected!
				t.Errorf("failed to detect access with id %s:\n%s\nof alloc at\n%s\n",
					wantSourceID.ID, wantSourceID.Pos, wantTargetID.Pos)
				if len(seenAccessOfAlloc[sTarget]) > 0 {
					// List possible sources for debugging
					t.Logf("Possible accesses:\n")
					for source := range seenAccessOfAlloc[sTarget] {
						t.Logf("\t%v\n", source)
					}
				}
			}
		}
	}
}

func debugResult(t *testing.T, want analysistest.TargetToSources, got passthru.AnalysisResult) {
	t.Logf("GOT result\n")
	str, _ := passthru.ReportResults(got)
	t.Log(str)

	t.Logf("WANT result\n")
	for target, sources := range want {
		t.Logf("\ttarget: %v\n", target.Pos)
		for source := range sources {
			t.Logf("\t\tsource: %v\n", source.Pos)
		}
	}
}
