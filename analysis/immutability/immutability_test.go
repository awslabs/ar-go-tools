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

package immutability_test

import (
	"embed"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/immutability"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

//go:embed testdata
var testfsys embed.FS

func TestAnalyze(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{name: "basic"},
	}

	for _, test := range tests {
		test := test

		result, err := runAnalysis(t, test.name)
		if err != nil {
			t.Fatal(err)
		}

		lp := result.lp
		got := result.result
		// res, _ := immutability.ReportResults(got)
		// t.Log(res)

		t.Run(test.name+":invalid-writes", func(t *testing.T) {
			want := wantInvalidWrites(lp)
			checkWrites(t, lp.Program, want, got.Modifications)
		})
		t.Run(test.name+":invalid-reads", func(t *testing.T) {
			want := wantInvalidReads(lp)
			checkReads(t, lp.Program, want, got.Modifications)
		})
		t.Run(test.name+":allocs", func(t *testing.T) {
			want := wantAllocs(lp)
			checkAllocs(t, lp.Program, want, got.Modifications)
		})
	}
}

func TestAnalyze_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{name: "invalid"},
	}

	for _, test := range tests {
		test := test
		result, err := runAnalysis(t, test.name)
		if !errors.Is(err, immutability.ErrEntrypointSelfReferential) {
			t.Errorf("expected analysis to have self-referential entrypoint, got: %v with error: %v", result, err)
		}
		if !errors.Is(err, immutability.ErrEntrypointNotPointer) {
			t.Errorf("expected analysis to have non-pointer-like entrypoint, got: %v with error: %v", result, err)
		}
	}
}

type runResult struct {
	lp     *loadprogram.State
	result immutability.AnalysisResult
}

func runAnalysis(t *testing.T, dirName string) (runResult, error) {
	dirName = filepath.Join("./testdata", dirName)
	lpState := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: false})
	lp, err := lpState.Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	setupConfig(lp.Config)
	state, err := result.Bind(lpState, ptr.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load pointer state: %v", err)
	}
	result, err := immutability.Analyze(state)
	if err != nil {
		return runResult{}, fmt.Errorf("immutability analysis failed: %w", err)
	}

	return runResult{lp: lp, result: result}, nil
}

func logMods(t *testing.T, res immutability.AnalysisResult) {
	for entry, mods := range res.Modifications {
		val := entry.Val
		t.Logf("Source: %v (%v) in %v at %v\n", val, val.Name(), val.Parent(), entry.Pos)
		for _, instr := range mods.Writes {
			pos := instr.Pos
			t.Logf("\twrite: %v in %v at %v\n", instr, instr.Parent(), pos)
		}
		for _, instr := range mods.Allocs {
			pos := instr.Pos
			t.Logf("\talloc: %v in %v at %v\n", instr, instr.Parent(), pos)
		}
	}
}

func setupConfig(cfg *config.Config) {
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(config.ErrLevel) // change this as needed for debugging
}

// immutableArgRegex matches annotations of the form "@ImmutableArg(id1, id2, id3)".
// An immutable arg is an argument that is configured to be immutable.
var immutableArgRegex = regexp.MustCompile(`//.*@ImmutableArg\(((?:\s*\w\s*,?)+)\)`)

// invalidWriteRegex matches annotations of the form "@InvalidWrite(id1, id2, id3)"
var invalidWriteRegex = regexp.MustCompile(`//.*@InvalidWrite\(((?:\s*\w\s*,?)+)\)`)

// invalidReadRegex matches annotations of the form "@InvalidRead(id1, id2, id3)"
var invalidReadRegex = regexp.MustCompile(`//.*@InvalidRead\(((?:\s*\w\s*,?)+)\)`)

// allocRegex matches annotations of the form "@Alloc(id1, id2, id3)"
var allocRegex = regexp.MustCompile(`//.*@Alloc\(((?:\s*\w\s*,?)+)\)`)

// wantInvalidWrites analyzes the files in lp and looks for comments
// @InvalidWrite(id1, id2, ...) to construct the expected positions of the
// invalid writes to a pointer.
// These positions are represented as a map from the argument value matching the
// id to all the invalid write operations' positions.
func wantInvalidWrites(lp *loadprogram.State) analysistest.TargetToSources {
	return wantTargetToSources(lp, immutableArgRegex, invalidWriteRegex)
}

// wantInvalidReads analyzes the files in lp and looks for comments
// @InvalidRead(id1, id2, ...) to construct the expected positions of the
// invalid reads to a pointer.
// These positions are represented as a map from the argument value matching the
// id to all the invalid read operations' positions.
func wantInvalidReads(lp *loadprogram.State) analysistest.TargetToSources {
	return wantTargetToSources(lp, immutableArgRegex, invalidReadRegex)
}

// wantAllocs analyzes the files in lp and looks for comments
// @Alloc(id1, id2, ...) to construct the expected positions of the allocations
// of a pointer.
// These positions are represented as a map from the argument value matching the
// id to all the allocations of that pointer.
func wantAllocs(lp *loadprogram.State) analysistest.TargetToSources {
	return wantTargetToSources(lp, immutableArgRegex, allocRegex)
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
		// Match a "@ImmutableArg(id1, id2, id3)"
		a := sourceRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				sourceIDToSourcePos[sourceIdent] = pos
			}
		}
	})

	// Get all the target positions
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		writePos := fset.Position(c1.Pos())
		// Match a "@InvalidWrite(id1, id2, id3)" or "@Alloc(id1, id2, id3)"
		a := targetRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				writeIdent := strings.TrimSpace(ident)
				sourcePos, ok := sourceIDToSourcePos[writeIdent]
				if !ok {
					continue
				}
				relTarget := analysistest.NewLPos(sourcePos)
				sourceId := analysistest.AnnotationID{ID: writeIdent, Meta: "", Pos: relTarget}
				if _, ok := target2sources[sourceId]; !ok {
					target2sources[sourceId] = make(map[analysistest.AnnotationID]bool)
				}
				// targetIdent is the same as sourceIdent in this branch
				writeId := analysistest.AnnotationID{
					ID:   writeIdent,
					Meta: "",
					Pos:  analysistest.NewLPos(writePos),
				}
				target2sources[sourceId][writeId] = true
			}
		}
	})

	return target2sources
}

// TODO refactor to remove duplicate code

// checkWrites checks that got's writes matches the wanted
// InvalidWrite->ImmutableArg annotation ids from the test.
func checkWrites(t *testing.T, prog *ssa.Program, want analysistest.TargetToSources, got map[immutability.Entrypoint]immutability.Modifications) {
	// debugWrites(t, want, got)

	type seenEntry struct {
		Pos analysistest.LPos
	}
	type seenWrite struct {
		Pos analysistest.LPos
	}
	seenWriteToEntry := make(map[seenEntry]map[seenWrite]bool)

	for entry, mods := range got {
		entryInstr := entry.Call
		entryPos := prog.Fset.Position(entryInstr.Pos())
		if !entryPos.IsValid() {
			t.Errorf("invalid entrypoint position for: %v", entryInstr)
			// skip invalid positions
			continue
		}
		gotEntry := seenEntry{Pos: analysistest.RemoveColumn(entryPos)}
		for _, writeInstr := range mods.Writes {
			if _, ok := seenWriteToEntry[gotEntry]; !ok {
				seenWriteToEntry[gotEntry] = map[seenWrite]bool{}
			}

			writePos := writeInstr.Pos
			if !writePos.IsValid() {
				t.Errorf("invalid write position for: %v", writeInstr)
				continue
			}
			gotWrite := seenWrite{Pos: analysistest.RemoveColumn(writePos)}
			seen := false
			for wantEntryID, wantWriteIDs := range want {
				if gotEntry.Pos == wantEntryID.Pos {
					for wantWriteID := range wantWriteIDs {
						if gotWrite.Pos == wantWriteID.Pos {
							seenWriteToEntry[seenEntry{wantEntryID.Pos}][seenWrite{wantWriteID.Pos}] = true
							seen = true
							break
						}
					}
				}
			}
			if !seen {
				t.Errorf("false positive: write %v to immutable argument at %v", writeInstr, gotEntry.Pos)
			}
		}
	}

	for wantEntryID, wantWriteIDs := range want {
		sEntry := seenEntry{Pos: wantEntryID.Pos}
		for wantWriteID := range wantWriteIDs {
			sWrite := seenWrite{Pos: wantWriteID.Pos}
			if !seenWriteToEntry[sEntry][sWrite] {
				// Remaining entries have not been detected!
				t.Errorf("failed to detect write with id %s:\n%s\nto argument at\n%s\n",
					wantWriteID.ID, wantWriteID.Pos, wantEntryID.Pos)
				if len(seenWriteToEntry[sEntry]) > 0 {
					// List possible writes for debugging
					t.Logf("Possible writes:\n")
					for entry := range seenWriteToEntry[sEntry] {
						t.Logf("\t%+v\n", entry)
					}
				}
			}
		}
	}
}

// checkReads checks that got's reads matches the wanted
// InvalidRead->ImmutableArg annotation ids from the test.
func checkReads(t *testing.T, prog *ssa.Program, want analysistest.TargetToSources, got map[immutability.Entrypoint]immutability.Modifications) {
	// debugReads(t, want, got)

	type seenEntry struct {
		Pos analysistest.LPos
	}
	type seenRead struct {
		Pos analysistest.LPos
	}
	seenReadToEntry := make(map[seenEntry]map[seenRead]bool)

	for entry, mods := range got {
		entryInstr := entry.Call
		entryPos := prog.Fset.Position(entryInstr.Pos())
		if !entryPos.IsValid() {
			t.Errorf("invalid entrypoint position for: %v", entryInstr)
			// skip invalid positions
			continue
		}
		gotEntry := seenEntry{Pos: analysistest.RemoveColumn(entryPos)}
		for _, readInstr := range mods.Reads {
			if _, ok := seenReadToEntry[gotEntry]; !ok {
				seenReadToEntry[gotEntry] = map[seenRead]bool{}
			}

			readPos := readInstr.Pos
			if !readPos.IsValid() {
				t.Errorf("invalid read position for: %v", readInstr)
				continue
			}
			gotRead := seenRead{Pos: analysistest.RemoveColumn(readPos)}
			seen := false
			for wantEntryID, wantReadIDs := range want {
				if gotEntry.Pos == wantEntryID.Pos {
					for wantReadID := range wantReadIDs {
						if gotRead.Pos == wantReadID.Pos {
							seenReadToEntry[seenEntry{wantEntryID.Pos}][seenRead{wantReadID.Pos}] = true
							seen = true
							break
						}
					}
				}
			}
			if !seen {
				t.Errorf("false positive: read %v to immutable argument at %v", readInstr, gotEntry.Pos)
			}
		}
	}

	for wantEntryID, wantReadIDs := range want {
		sEntry := seenEntry{Pos: wantEntryID.Pos}
		for wantReadID := range wantReadIDs {
			sRead := seenRead{Pos: wantReadID.Pos}
			if !seenReadToEntry[sEntry][sRead] {
				// Remaining entries have not been detected!
				t.Errorf("failed to detect read with id %s:\n%s\nto argument at\n%s\n",
					wantReadID.ID, wantReadID.Pos, wantEntryID.Pos)
				if len(seenReadToEntry[sEntry]) > 0 {
					// List possible reads for debugging
					t.Logf("Possible reads:\n")
					for entry := range seenReadToEntry[sEntry] {
						t.Logf("\t%+v\n", entry)
					}
				}
			}
		}
	}
}

// checkAllocs checks that got's allocs matches the wanted
// Alloc->ImmutableArg annotation ids from the test.
func checkAllocs(t *testing.T, prog *ssa.Program, want analysistest.TargetToSources, got map[immutability.Entrypoint]immutability.Modifications) {
	// debugAllocs(t, prog, want, got)

	type seenEntry struct {
		Pos analysistest.LPos
	}
	type seenAlloc struct {
		Pos analysistest.LPos
	}
	seenAllocToEntry := make(map[seenEntry]map[seenAlloc]bool)

	for entry, mods := range got {
		entryInstr := entry.Call
		entryPos := prog.Fset.Position(entryInstr.Pos())
		if !entryPos.IsValid() {
			t.Errorf("invalid entrypoint position for: %v", entryInstr)
			// skip invalid positions
			continue
		}
		gotEntry := seenEntry{Pos: analysistest.RemoveColumn(entryPos)}
		for _, allocInstr := range mods.Allocs {
			if _, ok := seenAllocToEntry[gotEntry]; !ok {
				seenAllocToEntry[gotEntry] = map[seenAlloc]bool{}
			}

			allocPos := allocInstr.Pos
			if !allocPos.IsValid() {
				t.Errorf("invalid alloc position for: %v", allocInstr)
				continue
			}
			gotAlloc := seenAlloc{Pos: analysistest.RemoveColumn(allocPos)}
			seen := false
			for wantEntryID, wantAllocIDs := range want {
				if gotEntry.Pos == wantEntryID.Pos {
					for wantAllocID := range wantAllocIDs {
						if gotAlloc.Pos == wantAllocID.Pos {
							seenAllocToEntry[seenEntry{wantEntryID.Pos}][seenAlloc{wantAllocID.Pos}] = true
							seen = true
							break
						}
					}
				}
			}
			if !seen {
				t.Errorf("false positive: alloc at %v to immutable argument at %v", gotAlloc.Pos, gotEntry.Pos)
			}
		}
	}

	for wantEntryID, wantAllocIDs := range want {
		sEntry := seenEntry{Pos: wantEntryID.Pos}
		for wantAllocID := range wantAllocIDs {
			sAlloc := seenAlloc{Pos: wantAllocID.Pos}
			if !seenAllocToEntry[sEntry][sAlloc] {
				// Remaining entries have not been detected!
				t.Errorf("failed to detect alloc with id %s:\n%s\nto argument at\n%s\n",
					wantAllocID.ID, wantAllocID.Pos, wantEntryID.Pos)
				if len(seenAllocToEntry[sEntry]) > 0 {
					// List possible allocs for debugging
					t.Logf("Possible allocs:\n")
					for entry := range seenAllocToEntry[sEntry] {
						t.Logf("\t%+v\n", entry)
					}
				}
			}
		}
	}
}

func debugWrites(t *testing.T, want analysistest.TargetToSources, got map[immutability.Entrypoint]immutability.Modifications) {
	t.Logf("GOT writes\n")
	for entry, mods := range got {
		t.Logf("\tentry: %v\n", entry.Pos)
		for _, write := range mods.Writes {
			t.Logf("\t\twrite: %v\n", write.Pos)
		}
	}

	t.Logf("WANT writes\n")
	for entry, writes := range want {
		t.Logf("\tentry: %v\n", entry.Pos)
		for write := range writes {
			t.Logf("\t\twrite: %v\n", write.Pos)
		}
	}
}

func debugReads(t *testing.T, want analysistest.TargetToSources, got map[immutability.Entrypoint]immutability.Modifications) {
	t.Logf("GOT reads\n")
	for entry, mods := range got {
		t.Logf("\tentry: %v\n", entry.Pos)
		for _, read := range mods.Reads {
			t.Logf("\t\tread: %v\n", read.Pos)
		}
	}

	t.Logf("WANT reads\n")
	for entry, reads := range want {
		t.Logf("\tentry: %v\n", entry.Pos)
		for read := range reads {
			t.Logf("\t\tread: %v\n", read.Pos)
		}
	}
}

func debugAllocs(t *testing.T, want analysistest.TargetToSources, got map[immutability.Entrypoint]immutability.Modifications) {
	t.Logf("GOT allocs\n")
	for entry, mods := range got {
		t.Logf("\tentry: %v\n", entry.Pos)
		for _, alloc := range mods.Allocs {
			t.Logf("\t\talloc: %v\n", alloc.Pos)
		}
	}

	t.Logf("WANT allocs\n")
	for entry, allocs := range want {
		t.Logf("\tentry: %v\n", entry.Pos)
		for alloc := range allocs {
			t.Logf("\t\talloc: %v\n", alloc.Pos)
		}
	}
}
