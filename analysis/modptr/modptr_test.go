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
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "taint", dirName)
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
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "taint", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	runTest(t, dir)
}

func runTest(t *testing.T, dir string) {
	lp := analysistest.LoadTest(t, ".", []string{})
	prog := lp.Program
	ptr, err := dataflow.DoPointerAnalysis(prog, func(*ssa.Function) bool { return true }, true)
	if err != nil {
		t.Fatalf("failed to run pointer analysis: %v", err)
	}

	res, err := modptr.Analyze(lp.Config, lp.LoadedProgram, ptr)
	if err != nil {
		t.Fatalf("failed to run analysis: %v", err)
	}

	expectedMods := analysistest.GetExpectedMods(dir, ".")
	checkExpectedPositions(t, prog, res, expectedMods)

	logMods(t, prog, res)
}

func checkExpectedPositions(t *testing.T, prog *ssa.Program, res modptr.Result, expect analysistest.SourceToTargets) {
	mods := res.Modifications
	// seenMod is a map from source position to mod positions
	seenMod := make(map[analysistest.LPos]map[analysistest.LPos]bool)

	for source, writes := range mods {
		sourcePos := source.Pos
		if !sourcePos.IsValid() {
			continue
		}
		sourceLPos := analysistest.RemoveColumn(sourcePos)
		if _, ok := seenMod[sourceLPos]; !ok {
			seenMod[sourceLPos] = make(map[analysistest.LPos]bool)
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

				for expectMod := range expectMods {
					if writeLPos != expectMod.Pos {
						continue
					}

					seenMod[sourceLPos][writeLPos] = true
					seen = true
				}
			}

			if !seen {
				// TODO false positives are not errors for now
				t.Logf("false positive: instruction %v at %v modifies source %v at %v\n", write, writePos, source.Val, sourcePos)
			}
		}
	}

	for expectSourceID, expectModIDs := range expect {
		for expectModID := range expectModIDs {
			if !seenMod[expectSourceID.Pos][expectModID.Pos] {
				t.Errorf("failed to detect that source %v is modified at %v\n", expectSourceID.ID, expectModID.Pos)
			}
		}
	}
}

func logMods(t *testing.T, prog *ssa.Program, res modptr.Result) {
	for entry, instrs := range res.Modifications {
		val := entry.Val
		t.Logf("VAL: %v (%v) in %v at %v\n", val, val.Name(), val.Parent(), entry.Pos)
		for instr := range instrs {
			pos := prog.Fset.Position(instr.Pos())
			t.Logf("\tMOD: %v in %v at %v\n", lang.FmtInstr(instr), instr.Parent(), pos)
		}
	}
}
