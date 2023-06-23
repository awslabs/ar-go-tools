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

package taint

import (
	"fmt"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"golang.org/x/tools/go/ssa"
)

func checkOnlyPositionsPresent(t *testing.T, actual map[token.Position]map[token.Position]bool,
	expect map[analysistest.LPos]map[analysistest.LPos]bool, falseAlarmFormat string, falsePositiveFormat string) {

	seenTaintFlow := make(map[analysistest.LPos]map[analysistest.LPos]bool)

	for sink, sources := range actual {
		for source := range sources {
			posSink := analysistest.RemoveColumn(sink)
			if _, ok := seenTaintFlow[posSink]; !ok {
				seenTaintFlow[posSink] = map[analysistest.LPos]bool{}
			}
			posSource := analysistest.RemoveColumn(source)
			if _, ok := expect[posSink]; ok && expect[posSink][posSource] {
				seenTaintFlow[posSink][posSource] = true
			} else {
				t.Errorf(falseAlarmFormat, posSource, posSink)
			}
		}
	}

	for sinkLine, sources := range expect {
		for sourceLine := range sources {
			if !seenTaintFlow[sinkLine][sourceLine] {
				// Remaining entries have not been detected!
				t.Errorf(falsePositiveFormat, sourceLine, sinkLine)
			}
		}
	}
}

func checkExpectedPositions(t *testing.T, p *ssa.Program, flows *Flows,
	expectTaint map[analysistest.LPos]map[analysistest.LPos]bool,
	expectEscapes map[analysistest.LPos]map[analysistest.LPos]bool) {

	actualTaintFlows, actualEscapes := flows.ToPositions(p)
	checkOnlyPositionsPresent(t, actualTaintFlows, expectTaint,
		"false positive:\n\t%s\n flows to\n\t%s\n",
		"failed to detect that:\n%s\nflows to\n%s\n")
	checkOnlyPositionsPresent(t, actualEscapes, expectEscapes,
		"false positive:\n%s\n escapes at\n%s\n",
		"failed to detect that:\n%s\nescapes at\n%s\n")
}

// runTest runs a test instance by building the program from all the files in files plus a file "main.go", relative
// to the directory dirName
func runTest(t *testing.T, dirName string, files []string) {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "taint", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	// The LoadTest function is relative to the testdata/src/taint-tracking-inter folder so we can
	// load an entire module with subpackages
	program, cfg := analysistest.LoadTest(t, ".", files)

	result, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expectSourceToSinks, expectSourceToEscape := analysistest.GetExpectSourceToTargets(dir, ".")
	checkExpectedPositions(t, program, result.TaintFlows, expectSourceToSinks, expectSourceToEscape)
	// Remove reports - comment if you want to inspect
	os.RemoveAll(cfg.ReportsDir)
}

// runTestSummarizeOnDemand runs a test instance by building the program from all the files in files plus a file "main.go", relative
// to the directory dirName and enables the SummarizeOnDemand configuration option.
func runTestSummarizeOnDemand(t *testing.T, dirName string, files []string) {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "taint", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	// The LoadTest function is relative to the testdata/src/taint-tracking-inter folder so we can
	// load an entire module with subpackages
	program, cfg := analysistest.LoadTest(t, ".", files)
	cfg.SummarizeOnDemand = true

	result, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expectSourceToSinks, expectSourceToEscape := analysistest.GetExpectSourceToTargets(dir, ".")
	checkExpectedPositions(t, program, result.TaintFlows, expectSourceToSinks, expectSourceToEscape)
	// Remove reports - comment if you want to inspect
	os.RemoveAll(cfg.ReportsDir)
}

func TestAll(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "src", "taint", "basic")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
	sink2source, _ := analysistest.GetExpectSourceToTargets(dir, ".")
	for sink, sources := range sink2source {
		for source := range sources {
			fmt.Printf("Source %s -> sink %s\n", source, sink)
		}
	}
}
