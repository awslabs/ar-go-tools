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

package passthru

import (
	"embed"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

//go:embed testdata/escapes
var testfsys embed.FS

func TestFindEscapes(t *testing.T) {
	dirName := filepath.Join("./testdata", "escapes")
	lpState := analysistest.LoadTest(testfsys, dirName, []string{},
		analysistest.LoadTestOptions{ApplyRewrite: false})
	lp, err := lpState.Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	setupConfig(lp.Config)
	state, err := result.Bind(result.Bind(lpState, ptr.NewState), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load dataflow state: %v", err)
	}
	wantFull := wantEscapes(lp)
	if len(wantFull) == 0 {
		t.Fatalf("failed to find any test file annotations")
	}

	tests := []struct {
		name string
	}{
		{name: "exParamLeak"},
		{name: "exParamOk"},
		{name: "exParamElemLeak"},
		{name: "exParamFieldLeak"},
		{name: "exParamFieldOk"},
		{name: "exArgLeak"},
		{name: "exFreeLeak"},
		{name: "exGlobalLeak"},
		{name: "exGlobalElemLeak"},
		{name: "exGlobalFieldLeak"},
		{name: "exInterOk"},
		{name: "exInterLeak"},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			want := make(analysistest.TargetToSources)
			var wantAllocIDs []analysistest.AnnotationID
			for allocID, escapeIDs := range wantFull {
				if allocID.ID == test.name {
					wantAllocIDs = append(wantAllocIDs, allocID)
					want[allocID] = escapeIDs
					break
				}
			}
			if len(wantAllocIDs) == 0 {
				t.Fatalf("failed to find any test file annotations with id: %v", test.name)
			}
			f, gotAllocs := findAllocs(&state.State, test.name, wantAllocIDs)
			if len(gotAllocs) == 0 {
				t.Fatalf("failed to find any core allocations with id: %v", test.name)
			}

			got := runEscapes(state, f, gotAllocs)
			checkEscapes(t, state.Program, want, got)
		})
	}
}

func runEscapes(state *dataflow.State, f *ssa.Function, allocs []AccessedCoreAlloc) []EscapedCoreAlloc {
	cache := ptr.NewAliasCache(&state.State)
	s := newState(state, cache, config.DiodonPassThroughSpec{})
	var escapes []EscapedCoreAlloc
	for _, alloc := range allocs {
		escs := findEscapes(s, f, alloc)
		escapes = append(escapes, EscapedCoreAlloc{alloc, escs})
	}

	return escapes
}

func findAllocs(state *ptr.State, funcName string, wantAllocIDs []analysistest.AnnotationID) (*ssa.Function, []AccessedCoreAlloc) {
	for f := range state.ReachableFunctions() {
		if f.Name() == funcName {
			var res []AccessedCoreAlloc
			lang.IterateInstructions(f, func(_ int, instr ssa.Instruction) {
				switch instr.(type) {
				case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
					for _, allocID := range wantAllocIDs {
						pos := state.Program.Fset.Position(instr.Pos())
						if analysistest.NewLPos(pos) == allocID.Pos {
							alloc := AccessedCoreAlloc{Value: instr.(ssa.Value), Pos: pos, trace: coreTrace{}}
							res = append(res, alloc)
						}
					}
				}
			})

			return f, res
		}
	}

	return nil, nil
}

func setupConfig(cfg *config.Config) {
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(config.ErrLevel) // change this as needed for debugging
}

// coreAllocRegex matches annotations of the form "@CoreAlloc(id1, id2, id3)"
var coreAllocRegex = regexp.MustCompile(`//.*@CoreAlloc\(((?:\s*\w\s*,?)+)\)`)

// escapeRegex matches annotations of the form "@Escape(id1, id2, id3)"
var escapeRegex = regexp.MustCompile(`//.*@Escape\(((?:\s*\w\s*,?)+)\)`)

// wantEscapes analyzes the files in lp and looks for comments
// @Escape(id1, id2, ...) to construct the expected positions of the
// escaped allocations.
// These positions are represented as a map from the allocation matching the
// id to all the escaped operations' positions.
func wantEscapes(lp *loadprogram.State) analysistest.TargetToSources {
	return wantTargetToSources(lp, coreAllocRegex, escapeRegex)
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
		// Match a "@CoreAlloc(id1, id2, id3)"
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
		// Match a "@Escape(id1, id2, id3)"
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
				writeId := analysistest.AnnotationID{
					ID:   targetIdent,
					Meta: "",
					Pos:  analysistest.NewLPos(targetPos),
				}
				target2sources[sourceId][writeId] = true
			}
		}
	})

	return target2sources
}

// TODO refactor to remove duplicate code

// checkWrites checks that got's writes matches the wanted
// CoreAlloc->Escape annotation ids from the test.
func checkEscapes(t *testing.T, prog *ssa.Program, want analysistest.TargetToSources, got []EscapedCoreAlloc) {
	// debugEscapes(t, want, got)

	type seenEntry struct {
		Pos analysistest.LPos
	}
	type seenEsc struct {
		Pos analysistest.LPos
	}
	seenEscOfEntry := make(map[seenEntry]map[seenEsc]bool)

	for _, escapedAlloc := range got {
		entryVal := escapedAlloc.AccessedCoreAlloc.Value
		entryPos := prog.Fset.Position(entryVal.Pos())
		if !entryPos.IsValid() {
			t.Errorf("invalid entrypoint position for: %v", entryVal)
			// skip invalid positions
			continue
		}
		gotEntry := seenEntry{Pos: analysistest.RemoveColumn(entryPos)}
		for _, escape := range escapedAlloc.Escapes {
			if _, ok := seenEscOfEntry[gotEntry]; !ok {
				seenEscOfEntry[gotEntry] = map[seenEsc]bool{}
			}

			writePos := escape.Pos
			if !writePos.IsValid() {
				t.Errorf("invalid escape position for: %v", escape)
				continue
			}
			gotWrite := seenEsc{Pos: analysistest.RemoveColumn(writePos)}
			seen := false
			for wantEntryID, wantWriteIDs := range want {
				if gotEntry.Pos == wantEntryID.Pos {
					for wantWriteID := range wantWriteIDs {
						if gotWrite.Pos == wantWriteID.Pos {
							seenEscOfEntry[seenEntry{wantEntryID.Pos}][seenEsc{wantWriteID.Pos}] = true
							seen = true
							break
						}
					}
				}
			}
			if !seen {
				t.Errorf("false positive: %v from core alloc at %v", escape, gotEntry.Pos)
			}
		}
	}

	for wantEntryID, wantEscIDs := range want {
		sEntry := seenEntry{Pos: wantEntryID.Pos}
		for wantEscID := range wantEscIDs {
			sEsc := seenEsc{Pos: wantEscID.Pos}
			if !seenEscOfEntry[sEntry][sEsc] {
				// Remaining entries have not been detected!
				t.Errorf("failed to detect escape with id %s:\n%s\nfrom alloc at\n%s\n",
					wantEscID.ID, wantEscID.Pos, wantEntryID.Pos)
				if len(seenEscOfEntry[sEntry]) > 0 {
					// List possible writes for debugging
					t.Logf("Possible escapes:\n")
					for esc := range seenEscOfEntry[sEntry] {
						t.Logf("\t%+v\n", esc)
					}
				}
			}
		}
	}
}

func debugEscapes(t *testing.T, want analysistest.TargetToSources, got []EscapedCoreAlloc) {
	t.Logf("GOT escapes\n")
	for _, alloc := range got {
		t.Logf("\talloc: %v\n", alloc.AccessedCoreAlloc.Pos)
		for _, escape := range alloc.Escapes {
			t.Logf("\t\tescape: %v\n", escape.Pos)
		}
	}

	t.Logf("WANT escapes\n")
	for entry, escs := range want {
		t.Logf("\talloc: %v\n", entry.Pos)
		for esc := range escs {
			t.Logf("\t\tescape: %v\n", esc.Pos)
		}
	}
}
