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

package taint_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

// checkTaint checks that actual matches the expected target->sink annotation ids from the test.
//
//gocyclo:ignore
func checkTaint(t *testing.T, prog *ssa.Program, expect analysistest.TargetToSources,
	actual map[taint.FlowNode]map[taint.FlowNode]bool) {
	type seenSource struct {
		Pos   analysistest.LPos
		Trace string
	}
	type seenSink struct {
		Pos analysistest.LPos
	}
	hasMeta := expect.HasMetadata()
	if hasMeta {
		t.Log("Test file has annotation metadata")
	}
	seenTaintFlow := make(map[seenSink]map[seenSource]bool)
	cmpSink := func(actual seenSink) func(analysistest.AnnotationID) bool {
		return func(expect analysistest.AnnotationID) bool {
			// sinks don't have metadata
			return actual.Pos == expect.Pos
		}
	}
	cmpSource := func(actual seenSource) func(analysistest.AnnotationID) bool {
		return func(expect analysistest.AnnotationID) bool {
			return actual.Pos == expect.Pos && actual.Trace == expect.Meta
		}
	}

	for sink, sources := range actual {
		sinkInstr := sink.Instr
		posSink, ok := taint.Position(prog, sinkInstr)
		if !ok {
			// skip invalid positions
			continue
		}
		actualSink := seenSink{Pos: analysistest.RemoveColumn(posSink)}
		for source := range sources {
			if _, ok := seenTaintFlow[actualSink]; !ok {
				seenTaintFlow[actualSink] = map[seenSource]bool{}
			}

			sourceInstr := source.Instr
			posSource, ok := taint.Position(prog, sourceInstr)
			if !ok {
				continue
			}
			trace := source.Trace
			if !hasMeta {
				// don't compare traces if the test file annotations do not have metadata
				trace = ""
			}
			actualSource := seenSource{Trace: trace, Pos: analysistest.RemoveColumn(posSource)}
			seen := false
			if expectSources := findExpectSourceIds(expect, cmpSink(actualSink)); len(expectSources) > 0 {
				if _, ok := findExpectSourceID(expectSources, cmpSource(actualSource)); ok {
					seenTaintFlow[actualSink][actualSource] = true
					seen = true
				}
			}
			if !seen {
				msg := fmt.Sprintf("false positive:\n%s\nwith trace: %s\nflows to\n%s\n",
					actualSource.Pos, actualSource.Trace, actualSink.Pos)
				if !hasMeta {
					t.Errorf(msg)
				} else {
					// TODO false positives are logs for now for tests with metadata until context-sensitivity is
					// improved
					t.Logf(msg)
				}
			}
		}
	}

	for expectSinkID, expectSourceIds := range expect {
		sSink := seenSink{Pos: expectSinkID.Pos}
		for expectSourceID := range expectSourceIds {
			sSource := seenSource{Pos: expectSourceID.Pos, Trace: expectSourceID.Meta}
			if !seenTaintFlow[sSink][sSource] {
				// Remaining entries have not been detected!
				if expectSourceID.Meta != "" {
					t.Errorf("failed to detect that source %s:\n%s\nwith trace: %s\nflows to\n%s\n",
						expectSourceID.ID, expectSourceID.Pos, expectSourceID.Meta, expectSinkID.Pos)
				} else {
					t.Errorf("failed to detect that source %s:\n%s\nflows to\n%s\n",
						expectSourceID.ID, expectSourceID.Pos, expectSinkID.Pos)
				}
				if len(seenTaintFlow[sSink]) > 0 {
					// List possible sources for debugging
					t.Logf("Possible sources:\n")
					for source := range seenTaintFlow[sSink] {
						t.Logf("\t%+v\n", source)
					}
				}
			}
		}
	}
}

func checkEscape(t *testing.T, prog *ssa.Program, expect analysistest.TargetToSources,
	actual map[ssa.Instruction]map[ssa.Instruction]df.EscapeRationale) {

	seenEscapeFlow := make(map[analysistest.LPos]map[analysistest.LPos]bool)
	cmpPos := func(pos analysistest.LPos) func(analysistest.AnnotationID) bool {
		return func(expectId analysistest.AnnotationID) bool {
			// just compare the positions
			return expectId.Pos == pos
		}
	}

	for escape, sources := range actual {
		escapePos, ok := taint.Position(prog, escape)
		if !ok {
			// skip invalid positions
			continue
		}
		posEscape := analysistest.RemoveColumn(escapePos)
		if _, ok := seenEscapeFlow[posEscape]; !ok {
			seenEscapeFlow[posEscape] = map[analysistest.LPos]bool{}
		}
		for source := range sources {
			sourcePos, ok := taint.Position(prog, source)
			if !ok {
				// skip invalid positions
				continue
			}
			posSource := analysistest.RemoveColumn(sourcePos)
			seen := false
			if expectSources := findExpectSourceIds(expect, cmpPos(posEscape)); len(expectSources) > 0 {
				if _, ok := findExpectSourceID(expectSources, cmpPos(posSource)); ok {
					seenEscapeFlow[posEscape][posSource] = true
					seen = true
				}
			}
			if !seen {
				t.Errorf("false positive:\n%s\n escapes at\n%s\n", posSource, posEscape)
			}
		}
	}

	for sinkID, sources := range expect {
		for sourceID := range sources {
			if !seenEscapeFlow[sinkID.Pos][sourceID.Pos] {
				// Remaining entries have not been detected!
				t.Errorf("failed to detect that:\n%s\nescapes at\n%s\n", sourceID.Pos, sinkID.Pos)
			}
		}
	}
}

// findExpectSourceIds returns all the source ids that match the target according to cmp.
func findExpectSourceIds(targetToSources analysistest.TargetToSources,
	cmp func(analysistest.AnnotationID) bool) map[analysistest.AnnotationID]bool {
	res := make(map[analysistest.AnnotationID]bool)
	for target, sources := range targetToSources {
		if cmp(target) {
			for source := range sources {
				res[source] = true
			}
		}
	}

	return res
}

func findExpectSourceID(sources map[analysistest.AnnotationID]bool,
	cmp func(analysistest.AnnotationID) bool) (analysistest.AnnotationID, bool) {
	for source := range sources {
		if cmp(source) {
			return source, true
		}
	}

	return analysistest.AnnotationID{}, false
}

func checkExpectedPositions(t *testing.T, p *ssa.Program, flows *taint.Flows, expectTaint analysistest.TargetToSources,
	expectEscapes analysistest.TargetToSources) {
	checkTaint(t, p, expectTaint, flows.Sinks)
	checkEscape(t, p, expectEscapes, flows.Escapes)
}

func noErrorExpected(_ error) bool {
	return false
}

// expectTaintCondInFuncs returns a function that returns true when the supplied
// CondError's callee is in funcNames.
//
// Note: the tests are implemented this way because *ssa.If does not store any position data
func expectTaintedCondInFuncs(funcNames ...string) func(error) bool {
	return func(err error) bool {
		var e *taint.CondError
		if !errors.As(err, &e) {
			return false
		}

		for _, calleeName := range funcNames {
			if e.ParentName == calleeName {
				return true
			}
		}

		return false
	}
}

// runTest runs a test instance by building the program from all the files in files plus a file "main.go", relative
// to the test directory dirName.
func runTest(t *testing.T, dirName string, files []string, summarizeOnDemand bool, errorExpected func(e error) bool) {
	res := runTestWithoutCheck(t, dirName, files, summarizeOnDemand, errorExpected)
	lp, err := res.lp.Value()
	if err != nil {
		t.Fatalf("failed to run test: %s", err)
	}
	inner := res.res

	if inner.TaintFlows == nil {
		t.Fatal("no result taint flows found")
	}
	if len(inner.TaintFlows.Sinks) == 0 {
		t.Fatal("no taint flows to sinks found")
	}

	astFs := analysistest.AstFiles(lp.Packages)
	expectSinkToSources, expectEscapeToSources := expectedTaintTargetToSources(lp.Program.Fset, astFs)

	if len(expectSinkToSources) == 0 {
		t.Fatal("no expected taint flows found")
	}

	checkExpectedPositions(t, lp.Program, inner.TaintFlows, expectSinkToSources, expectEscapeToSources)
	// Remove reports - comment if you want to inspect
	os.RemoveAll(lp.Config.ReportsDir)
}

type runTestResult struct {
	lp  result.Result[loadprogram.State]
	res taint.AnalysisResult
}

// runTestWithoutCheck runs the test without checking expected flows.
func runTestWithoutCheck(t *testing.T, dirName string, files []string, summarizeOnDemand bool, errorExpected func(e error) bool) runTestResult {
	dirName = filepath.Join("./testdata", dirName)
	lp := analysistest.LoadTest(testfsys, dirName, files, analysistest.LoadTestOptions{ApplyRewrite: false})
	if lp.IsErr() {
		t.Fatalf("failed to load test: %v", lp)
	}
	result.Do(lp, func(lp *loadprogram.State) { setupConfig(lp.Config, summarizeOnDemand) })
	ptrState := result.Bind(lp, ptr.NewState)
	state, err := result.Bind(ptrState, dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to initialize state")
	}
	res, err := taint.Analyze(state, taint.AnalysisReqs{})
	if err != nil {
		if res.State != nil {
			for _, err := range res.State.Report.CheckError() {
				if !errorExpected(err) {
					t.Errorf("taint analysis returned error: %v", err)
				}
			}
		}
	}

	return runTestResult{
		lp:  lp,
		res: res,
	}
}

func setupConfig(cfg *config.Config, summarizeOnDemand bool) {
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(config.ErrLevel) // change this as needed for debugging
	cfg.SummarizeOnDemand = summarizeOnDemand
}

// sourceRegex matches an annotation of the form @Source(id1, id2 meta2, ...)
// where the "argument" is either an identifier (e.g. id) or an identifier with
// associated "metadata" (e.g. id call:example1->call:helper->call:example1$1).
var sourceRegex = regexp.MustCompile(`//.*@Source\(((?:\s*(\w|(\w\s+[a-zA-Z0-9$:\->]+\s*))\s*,?)+)\)`)

// sinkRegex matches annotations of the form "@Sink(id1, id2, id3)"
var sinkRegex = regexp.MustCompile(`//.*@Sink\(((?:\s*\w\s*,?)+)\)`)

// escapeRegex matches annotations of the form "@Escape(id1, id2, id3)"
var escapeRegex = regexp.MustCompile(`//.*@Escape\(((?:\s*\w\s*,?)+)\)`)

// expectedTaintTargetToSources analyzes the files in astFiles
// and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from targets to sources in the form of two maps from:
// - from sink positions to all the source position that reach that sink.
// - from escape positions to the source of data that escapes.
func expectedTaintTargetToSources(fset *token.FileSet, astFiles []*ast.File) (analysistest.TargetToSources, analysistest.TargetToSources) {
	sink2source := make(analysistest.TargetToSources)
	escape2source := make(analysistest.TargetToSources)
	type sourceInfo struct {
		meta string
		pos  token.Position
	}
	sourceIDToSource := map[string]sourceInfo{}

	// Get all the source positions with their identifiers
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "@Source(id1, id2, id3 meta)"
		a := sourceRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sourceIdent := strings.TrimSpace(ident)
				split := strings.Split(sourceIdent, " ")
				meta := ""
				// If id has metadata as in @Source(id meta), then sourceIdent is id and meta is "meta"
				if len(split) == 2 {
					sourceIdent = split[0]
					meta = split[1]
				}
				sourceIDToSource[sourceIdent] = sourceInfo{meta: meta, pos: pos}
			}
		}
	})

	// Get all the sink positions
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		sinkPos := fset.Position(c1.Pos())
		// Match a "@Sink(id1, id2, id3)"
		a := sinkRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				sinkIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIDToSource[sinkIdent]; ok {
					relSink := analysistest.NewLPos(sinkPos)
					// sinks do not have metadata
					sinkAnnotation := analysistest.AnnotationID{ID: sinkIdent, Meta: "", Pos: relSink}
					if _, ok := sink2source[sinkAnnotation]; !ok {
						sink2source[sinkAnnotation] = make(map[analysistest.AnnotationID]bool)
					}
					// sinkIdent is the same as sourceIdent in this branch
					sourceAnnotation := analysistest.AnnotationID{
						ID:   sinkIdent,
						Meta: sourcePos.meta,
						Pos:  analysistest.NewLPos(sourcePos.pos),
					}
					sink2source[sinkAnnotation][sourceAnnotation] = true
				}
			}
		}
	})

	// Get all the escape positions
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		escapePos := fset.Position(c1.Pos())
		// Match a "@Escape(id1, id2, id3)"
		a := escapeRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			for _, ident := range strings.Split(a[1], ",") {
				escapeIdent := strings.TrimSpace(ident)
				if sourcePos, ok := sourceIDToSource[escapeIdent]; ok {
					relEscape := analysistest.NewLPos(escapePos)
					// escapes do not have metadata
					escapeAnnotation := analysistest.AnnotationID{ID: escapeIdent, Meta: "", Pos: relEscape}
					if _, ok := escape2source[escapeAnnotation]; !ok {
						escape2source[escapeAnnotation] = make(map[analysistest.AnnotationID]bool)
					}
					// escapeIdent is the same as sourceIdent in this branch
					sourceAnnotation := analysistest.AnnotationID{
						ID:   escapeIdent,
						Meta: sourcePos.meta,
						Pos:  analysistest.NewLPos(sourcePos.pos),
					}
					escape2source[escapeAnnotation][sourceAnnotation] = true
				}
			}
		}
	})

	return sink2source, escape2source
}
