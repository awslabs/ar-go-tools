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

package modptr_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/modptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"golang.org/x/tools/go/ssa"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "basic"},
		// {name: "data"},
	}

	for _, test := range tests {
		// Change directory to the testdata folder to be able to load packages
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "modptr", test.name)
		err := os.Chdir(dir)
		if err != nil {
			panic(err)
		}

		runTest(t, dir)
	}
}

func TestAnalyze_DiodonExample(t *testing.T) {
	// Change directory to the testdata folder to be able to load packages
	dirName := "diodon-example"
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "diodon", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	runTest(t, dir)
}

func TestAnalyze_DiodonAgent(t *testing.T) {
	// Change directory to the testdata folder to be able to load packages
	dirName := "diodon-agent"
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "diodon", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	runTest(t, dir)
}

func runTest(t *testing.T, dir string) {
	lp := analysistest.LoadTest(t, ".", []string{})
	prog := lp.Program
	goPtrRes, err := dataflow.DoPointerAnalysis(prog, func(*ssa.Function) bool { return true }, true)
	if err != nil {
		t.Fatalf("failed to run pointer analysis: %v", err)
	}
	ptrRes, err := modptr.DoPointerAnalysis(prog, func(*ssa.Function) bool { return true }, true)
	if err != nil {
		t.Fatalf("failed to run pointer analysis: %v", err)
	}

	res, err := modptr.Analyze(lp.Config, lp.LoadedProgram, ptrRes, goPtrRes)
	if err != nil {
		t.Fatalf("failed to run analysis: %v", err)
	}
	if len(res.Modifications) == 0 {
		t.Error("no modifications detected")
	}

	expectedMods := analysistest.GetExpectedMods(dir, ".")
	checkExpectedPositions(t, prog, res, expectedMods)

	logMods(t, prog, res)
}

func checkExpectedPositions(t *testing.T, prog *ssa.Program, res modptr.Result, expect map[analysistest.AnnotationID]analysistest.ExpectedMods) {
	mods := res.Modifications
	// seenWrite is a map from source position to write positions
	seenWrite := make(map[analysistest.LPos]map[analysistest.LPos]bool)
	// seenAlloc is a map from source position to alloc positions
	seenAlloc := make(map[analysistest.LPos]map[analysistest.LPos]bool)

	for source, sourceMods := range mods {
		writes := sourceMods.Writes
		sourcePos := source.Pos
		if !sourcePos.IsValid() {
			continue
		}
		sourceLPos := analysistest.RemoveColumn(sourcePos)
		if _, ok := seenWrite[sourceLPos]; !ok {
			seenWrite[sourceLPos] = make(map[analysistest.LPos]bool)
		}
		if _, ok := seenAlloc[sourceLPos]; !ok {
			seenAlloc[sourceLPos] = make(map[analysistest.LPos]bool)
		}

		for write := range writes {
			writePos := prog.Fset.Position(write.Pos())
			if !writePos.IsValid() {
				continue
			}

			writeLPos := analysistest.RemoveColumn(writePos)
			seen := false
			for expectSource, expectMods := range expect {
				if sourceLPos != expectSource.Pos {
					continue
				}

				for expectWrite := range expectMods.Writes {
					if writeLPos != expectWrite.Pos {
						continue
					}

					seenWrite[sourceLPos][writeLPos] = true
					seen = true
				}
			}

			if !seen {
				// TODO false positives are not errors for now
				t.Logf("false positive: instruction %v at %v writes to source %v at %v\n", write, writePos, source.Val, sourcePos)
			}
		}

		allocs := sourceMods.Allocs
		for alloc := range allocs {
			allocPos := prog.Fset.Position(alloc.Pos())
			if !allocPos.IsValid() {
				continue
			}

			allocLPos := analysistest.RemoveColumn(allocPos)
			seen := false
			for expectSource, expectMods := range expect {
				if sourceLPos != expectSource.Pos {
					continue
				}

				for expectAlloc := range expectMods.Allocs {
					if allocLPos != expectAlloc.Pos {
						continue
					}

					seenAlloc[sourceLPos][allocLPos] = true
					seen = true
				}
			}

			if !seen {
				// TODO false positives are not errors for now
				t.Logf("false positive: instruction %v at %v allocates an alias to source data %v at %v\n", alloc, allocPos, source.Val, sourcePos)
			}
		}
	}

	for expectSourceID, expectMods := range expect {
		for expectWriteID := range expectMods.Writes {
			if !seenWrite[expectSourceID.Pos][expectWriteID.Pos] {
				t.Errorf("failed to detect that source %v is written to at %v\n", expectSourceID.ID, expectWriteID.Pos)
			}
		}

		for expectAllocID := range expectMods.Allocs {
			if !seenAlloc[expectSourceID.Pos][expectAllocID.Pos] {
				t.Errorf("failed to detect that an alias to source %v is allocated at %v\n", expectSourceID.ID, expectAllocID.Pos)
			}
		}
	}
}

func logMods(t *testing.T, prog *ssa.Program, res modptr.Result) {
	for entry, mods := range res.Modifications {
		val := entry.Val
		t.Logf("Source: %v (%v) in %v at %v\n", val, val.Name(), val.Parent(), entry.Pos)
		for instr := range mods.Writes {
			pos := prog.Fset.Position(instr.Pos())
			t.Logf("\twrite: %v in %v at %v\n", lang.FmtInstr(instr), instr.Parent(), pos)
		}
		for instr := range mods.Allocs {
			pos := prog.Fset.Position(instr.Pos())
			t.Logf("\talloc: %v in %v at %v\n", lang.FmtInstr(instr), instr.Parent(), pos)
		}
	}
}
