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
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
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
	setupConfig(lp.Config)
	state, err := result.Bind(lpState, ptr.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load pointer state: %v", err)
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
}

func setupConfig(cfg *config.Config) {
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(config.ErrLevel) // change this as needed for debugging
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
	return wantTargetToSources(lp, invalidAccessRegex, coreAllocRegex)
}

// wantTargetToSources analyzes the files in lp and looks for comments
// matching sourceRegex and targetRegex to construct expected matches from
// targets to sources in the form of a map of target positions to all the source
// positions that reach that target.
func wantTargetToSources(lp *loadprogram.State, sourceRegex *regexp.Regexp, targetRegex *regexp.Regexp) analysistest.TargetToSources {
	astFiles := analysistest.AstFiles(lp.Packages)
	fset := lp.Program.Fset
	target2sources := make(analysistest.TargetToSources)
	type sourceInfo struct {
		meta string
		pos  token.Position
	}
	sourceIDToSourcePos := map[string]token.Position{}

	// Get all the source positions with their identifiers
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "@InvalidAccess(id1, id2, id3)"
		a := sourceRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				sourceIDToSourcePos[sourceIdent] = pos
				relSource := analysistest.NewLPos(pos)
				id := analysistest.AnnotationID{ID: sourceIdent, Meta: "", Pos: relSource}
				target2sources[id] = make(map[analysistest.AnnotationID]bool)
			}
		}
	})

	// Get all the target positions
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		targetPos := fset.Position(c1.Pos())
		// Match a "@CoreAlloc(id1, id2, id3)"
		a := targetRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				targetIdent := strings.TrimSpace(ident)
				sourcePos, ok := sourceIDToSourcePos[targetIdent]
				if !ok {
					continue
				}
				relTarget := analysistest.NewLPos(sourcePos)
				sourceId := analysistest.AnnotationID{ID: targetIdent, Meta: "", Pos: relTarget}
				if _, ok := target2sources[sourceId]; !ok {
					target2sources[sourceId] = make(map[analysistest.AnnotationID]bool)
				}
				// targetIdent is the same as sourceIdent in this branch
				targetId := analysistest.AnnotationID{
					ID:   targetIdent,
					Meta: "",
					Pos:  analysistest.NewLPos(targetPos),
				}
				target2sources[sourceId][targetId] = true
			}
		}
	})

	return target2sources
}

// TODO refactor to remove duplicate code

// checkWrites checks that got's writes matches the wanted
// InvalidAccess->CoreAlloc annotation ids from the test.
func checkInvalidAccesses(t *testing.T, prog *ssa.Program, want analysistest.TargetToSources, got passthru.AnalysisResult) {
	debugResult(t, want, got)

	type seenEntry struct {
		Pos analysistest.LPos
	}
	type seenAlloc struct {
		Pos analysistest.LPos
	}
	seenAllocOfEntry := make(map[seenEntry]map[seenAlloc]bool)

	for _, access := range got.InvalidAccesses {
		entryInstr := access.Instruction
		entryPos := prog.Fset.Position(entryInstr.Pos())
		if !entryPos.IsValid() {
			t.Errorf("invalid entrypoint position for: %v", entryInstr)
			// skip invalid positions
			continue
		}
		gotEntry := seenEntry{Pos: analysistest.RemoveColumn(entryPos)}
		for alloc := range access.EscapedAllocs {
			if _, ok := seenAllocOfEntry[gotEntry]; !ok {
				seenAllocOfEntry[gotEntry] = map[seenAlloc]bool{}
			}

			allocPos := alloc.Pos
			if !allocPos.IsValid() {
				t.Errorf("invalid position for: %v", alloc)
				continue
			}
			gotWrite := seenAlloc{Pos: analysistest.RemoveColumn(allocPos)}
			seen := false
			for wantEntryID, wantAllocIDs := range want {
				if gotEntry.Pos == wantEntryID.Pos {
					for wantAllocID := range wantAllocIDs {
						if gotWrite.Pos == wantAllocID.Pos {
							seenAllocOfEntry[seenEntry{wantEntryID.Pos}][seenAlloc{wantAllocID.Pos}] = true
							seen = true
							break
						}
					}
				}
			}
			if !seen {
				t.Errorf("false positive: %v from invalid access at %v", alloc, gotEntry.Pos)
			}
		}
	}

	for wantEntryID, wantAllocIDs := range want {
		sEntry := seenEntry{Pos: wantEntryID.Pos}
		for wantAllocID := range wantAllocIDs {
			sAlloc := seenAlloc{Pos: wantAllocID.Pos}
			if !seenAllocOfEntry[sEntry][sAlloc] {
				// Remaining entries have not been detected!
				t.Errorf("failed to detect core alloc with id %s:\n%s\nfrom invalid access at\n%s\n",
					wantAllocID.ID, wantAllocID.Pos, wantEntryID.Pos)
				if len(seenAllocOfEntry[sEntry]) > 0 {
					// List possible targets for debugging
					t.Logf("Possible core allocs:\n")
					for alloc := range seenAllocOfEntry[sEntry] {
						t.Logf("\t%+v\n", alloc)
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
	for entry, allocs := range want {
		t.Logf("\tinvalid access: %v\n", entry.Pos)
		for acc := range allocs {
			t.Logf("\t\tcore alloc: %v\n", acc.Pos)
		}
	}
}
