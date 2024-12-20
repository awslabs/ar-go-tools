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

package backtrace_test

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/backtrace"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	resultMonad "github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

// TestBacktraceTaint repurposes the taint analysis tests to test the backtrace analysis.
// The marked @Source and @Sink locations in the test files correspond to expected sources and sinks.
// These tests check the invariant that for every trace entrypoint (corresponding to the sinks),
// the expected source must exist somewhere in the trace.
func TestBacktraceTaint(t *testing.T) {
	tests := []testDef{
		{"basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "memory.go"}},
		{"builtins", []string{"helpers.go"}},
		// TODO backtrace needs updating
		{"interfaces", []string{}},
		{"parameters", []string{}},
		{"example1", []string{}},
		{"example2", []string{}},
		{"defers", []string{}},
		{"closures", []string{"helpers.go"}},
		// TODO: fix false positives
		// {"closures_flowprecise", []string{"helpers.go"}},
		{"closures_paper", []string{"helpers.go"}},
		// TODO fix false positives
		// {"fromlevee", []string{}},
		{"globals", []string{"helpers.go"}},
		{"stdlib", []string{"helpers.go"}},
		{"selects", []string{"helpers.go"}},
		{"tuples", []string{}},
		{"panics", []string{}},
	}

	for _, test := range tests {
		test := test
		for _, isOnDemand := range []bool{false, true} {
			name := test.name
			if isOnDemand {
				name += "_OnDemand"
			}
			t.Run(name, func(t *testing.T) { runBacktraceTest(t, test, isOnDemand) })
		}
	}
}

type testDef struct {
	name  string
	files []string
}

func runBacktraceTest(t *testing.T, test testDef, isOnDemand bool) {
	// Note: this is how you run the test via the OS file system, instead of using the embedded file system
	// _, filename, _, _ := runtime.Caller(0)
	// dir := filepath.Join(path.Dir(filename))
	// // filesystem root is <...>/analysis/taint
	// // this is needed to get the proper path names when creating the Go packages
	// fsys := os.DirFS(dir)
	// lp, err := analysistest.LoadTest(fsys.(analysistest.ReadFileDirFS), filepath.Join("testdata", test.name), test.files)

	dir := filepath.Join("./testdata", test.name)
	lp, err := analysistest.LoadTest(testfsys, dir, test.files, analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	setupConfig(lp, isOnDemand)

	astFiles := analysistest.AstFiles(lp.Packages)
	expected := expectedTaintTargetToSources(lp.Program.Fset, astFiles)
	if len(expected) == 0 {
		t.Fatal("expected sources and sinks to be present")
	}
	hasMeta := expected.HasMetadata()
	if hasMeta {
		t.Log("test file has annotation metadata")
	}

	if len(lp.Config.TaintTrackingProblems) < 1 {
		t.Fatal("expect at least one taint tracking problem")
	}
	lp.Config.SlicingProblems = []config.SlicingSpec{{BacktracePoints: lp.Config.TaintTrackingProblems[0].Sinks}}
	state, err := resultMonad.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load dataflow state: %s", err)
	}
	res, err := backtrace.Analyze(state, backtrace.AnalysisReqs{})
	if err != nil {
		t.Fatalf("failed to run analysis: %v", err)
	}

	// Uncomment for debugging
	// t.Log("TRACES:")
	// for _, trace := range res.Traces {
	// 	t.Log(trace)
	// }

	reached := reachedSinkPositions(state, res)
	if len(reached) == 0 {
		t.Fatal("expected reached sink positions to be present")
	}

	// Uncomment for debugging
	// for sink, sources := range reached {
	// 	t.Logf("sink: %v -> sources: %v", sink, sources)
	// }

	seen := make(map[analysistest.LPos]map[analysistest.LPos]bool)
	for sink, sources := range reached {
		for source := range sources {
			posSink := analysistest.RemoveColumn(sink)
			if _, ok := seen[posSink]; !ok {
				seen[posSink] = map[analysistest.LPos]bool{}
			}
			posSource := analysistest.RemoveColumn(source)
			if isExpected(expected, posSource, posSink) {
				seen[posSink][posSource] = true
			} else if !strings.HasPrefix(posSink.Filename, dir) {
				// TODO: check that the on-demand summarization is consistent with the not on-demand when analyzing
				// the standard library
				t.Log("WARNING: detected path outside of test repository.")
			} else {
				t.Errorf("ERROR in main.go: false positive:\n\t%s\n flows to\n\t%s\n", posSource, posSink)
			}
		}
	}

	for expectSink, expectSources := range expected {
		for expectSource := range expectSources {
			if expectSource.Meta != "" {
				t.Logf("WARN: failed to detect that:\n%s\nflows to\n%s\n", expectSource, expectSink)
				continue
			}

			if !seen[expectSink.Pos][expectSource.Pos] {
				// Remaining entries have not been detected!
				t.Errorf("ERROR: failed to detect that:\n%s\nflows to\n%s\n", expectSource, expectSink)
			}
		}
	}
}

func isExpected(expected analysistest.TargetToSources, sourcePos analysistest.LPos, sinkPos analysistest.LPos) bool {
	for sink, sources := range expected {
		if sink.Pos == sinkPos {
			for source := range sources {
				if source.Pos == sourcePos {
					return true
				}
			}
		}
	}

	return false
}

// reachedSinkPositions translates a list of traces in a program to a map from positions to set of positions,
// where the map associates sink positions to sets of source positions that reach it.
func reachedSinkPositions(s *dataflow.State, res backtrace.AnalysisResult) map[token.Position]map[token.Position]bool {
	positions := make(map[token.Position]map[token.Position]bool)
	prog := s.Program
	for sink, traces := range res.Traces[""] {
		// sink is the analysis entrypoint
		si := dataflow.Instr(sink)
		if si == nil {
			continue
		}
		sinkPos := si.Pos()
		sinkFile := prog.Fset.File(sinkPos)
		if sinkPos == token.NoPos || sinkFile == nil {
			continue
		}

		sinkP := sinkFile.Position(sinkPos)
		if _, ok := positions[sinkP]; !ok {
			positions[sinkP] = map[token.Position]bool{}
		}

		for _, trace := range traces {
			for _, node := range trace {
				instr := dataflow.Instr(node.GraphNode)
				if instr == nil {
					continue
				}

				sn := sourceNode(node.GraphNode)
				if dataflow.IsSourceNode(s, nil, sn) {
					sourcePos := instr.Pos()
					sourceFile := prog.Fset.File(sourcePos)
					if sourcePos == token.NoPos || sourceFile == nil {
						continue
					}

					sourceP := sourceFile.Position(sourcePos)
					positions[sinkP][sourceP] = true
				}
			}
		}
	}

	return positions
}

func sourceNode(source dataflow.GraphNode) ssa.Node {
	switch node := source.(type) {
	case *dataflow.CallNode:
		return node.CallSite().Value()
	case *dataflow.CallNodeArg:
		return node.ParentNode().CallSite().Value()
	case *dataflow.SyntheticNode:
		return node.Instr().(ssa.Node)
	default:
		panic(fmt.Errorf("invalid source: %T", source))
	}
}

// The following code is copied from taint_utils_test.go

// sourceRegex matches an annotation of the form @Source(id1, id2 meta2, ...)
// where the "argument" is either an identifier (e.g. id) or an identifier with
// associated "metadata" (e.g. id call:example1->call:helper->call:example1$1).
var sourceRegex = regexp.MustCompile(`//.*@Source\(((?:\s*(\w|(\w\s+[a-zA-Z0-9$:\->]+\s*))\s*,?)+)\)`)

// sinkRegex matches annotations of the form "@Sink(id1, id2, id3)"
var sinkRegex = regexp.MustCompile(`//.*@Sink\(((?:\s*\w\s*,?)+)\)`)

// expectedTaintTargetToSources analyzes the files in astFiles
// and looks for comments @Source(id) and @Sink(id) to construct
// expected flows from targets to sources in the form of a map of
// sink positions to all the source positions that reach that sink.
func expectedTaintTargetToSources(fset *token.FileSet, astFiles []*ast.File) analysistest.TargetToSources {
	sink2source := make(analysistest.TargetToSources)
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

	return sink2source
}

func mergeTraces(result backtrace.AnalysisResult) []backtrace.Trace {
	n := 0
	for _, traces := range result.Traces {
		n += len(traces)
	}
	res := make([]backtrace.Trace, 0, n)
	for _, traces := range result.Traces[""] {
		res = append(res, traces...)
	}

	return res
}
