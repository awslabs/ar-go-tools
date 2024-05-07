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
	"fmt"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/backtrace"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/go/ssa"
)

// TestBacktraceTaint repurposes the taint analysis tests to test the backtrace analysis.
// The marked @Source and @Sink locations in the test files correspond to expected sources and sinks.
// These tests check the invariant that for every trace entrypoint (corresponding to the sinks),
// the expected source must exist somewhere in the trace.
func TestBacktraceTaint(t *testing.T) {
	tests := []testDef{
		{"basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go",
			"sanitizers.go", "memory.go", "channels.go"}},
		{"builtins", []string{"helpers.go"}},
		// TODO backtrace needs updating
		//{"interfaces", []string{}},
		// TODO backtrace needs updating
		//{"parameters", []string{}},
		{"example1", []string{}},
		{"example2", []string{}},
		{"defers", []string{}},
		{"closures", []string{"helpers.go"}},
		// TODO: fix false positives
		// {"closures_flowprecise", []string{"helpers.go"}},
		// TODO fix false positives
		// {"fromlevee", []string{}},
		{"globals", []string{"helpers.go"}},
		{"stdlib", []string{"helpers.go"}},
		{"selects", []string{"helpers.go"}},
		{"panics", []string{}},
		{"closures_paper", []string{"helpers.go"}},
	}

	skip := map[string]bool{
		"fields.go":     true, // struct fields as backtracepoints are not supported yet
		"sanitizers.go": true, // backtrace does not consider sanitizers - that is a taint-analysis-specific feature
		"channels.go":   true, // backtrace doesn't trace channel reads as sources
	}

	for _, test := range tests {
		test := test
		for _, isOnDemand := range []bool{false, true} {
			name := test.name
			if isOnDemand {
				name += "_OnDemand"
			}
			t.Run(name, func(t *testing.T) { runBacktraceTest(t, test, isOnDemand, skip) })
		}
	}
}

type testDef struct {
	name  string
	files []string
}

func runBacktraceTest(t *testing.T, test testDef, isOnDemand bool, skip map[string]bool) {
	// Note: this is how you run the test via the OS file system, instead of using the embedded file system
	// _, filename, _, _ := runtime.Caller(0)
	// dir := filepath.Join(path.Dir(filename))
	// // filesystem root is <...>/analysis/taint
	// // this is needed to get the proper path names when creating the Go packages
	// fsys := os.DirFS(dir)
	// lp, err := analysistest.LoadTest(fsys.(analysistest.ReadFileDirFS), filepath.Join("testdata", test.name), test.files)

	dir := filepath.Join("./testdata", test.name)
	lp, err := analysistest.LoadTest(testfsys, dir, test.files)
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	program := lp.Prog
	setupConfig(lp.Config, isOnDemand)
	cfg := lp.Config

	astFiles := analysistest.AstFiles(lp.Pkgs)
	expected, _ := expectedTaintTargetToSources(lp.Prog.Fset, astFiles)
	if len(expected) == 0 {
		t.Fatal("expected sources and sinks to be present")
	}
	hasMeta := expected.HasMetadata()
	if hasMeta {
		t.Log("test file has annotation metadata")
	}

	if len(cfg.TaintTrackingProblems) < 1 {
		t.Fatal("expect at least one taint tracking problem")
	}
	cfg.SlicingProblems = []config.SlicingSpec{{BacktracePoints: cfg.TaintTrackingProblems[0].Sinks}}
	log := config.NewLogGroup(cfg)
	res, err := backtrace.Analyze(log, cfg, program)
	if err != nil {
		t.Fatal(err)
	}

	// Uncomment for debugging
	// t.Log("TRACES:")
	// for _, trace := range res.Traces {
	// 	t.Log(trace)
	// }

	reached := reachedSinkPositions(program, cfg, res.Traces)
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
			if skip[filepath.Base(source.Filename)] || skip[filepath.Base(sink.Filename)] {
				continue
			}

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
			if skip[filepath.Base(expectSource.Pos.Filename)] || skip[filepath.Base(expectSink.Pos.Filename)] {
				continue
			}
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
func reachedSinkPositions(prog *ssa.Program, cfg *config.Config,
	traces []backtrace.Trace) map[token.Position]map[token.Position]bool {
	positions := make(map[token.Position]map[token.Position]bool)
	for _, trace := range traces {
		// sink is always the last node in the trace because it's the analysis entrypoint
		sink := trace[len(trace)-1]
		si := dataflow.Instr(sink.GraphNode)
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

		for _, node := range trace {
			instr := dataflow.Instr(node.GraphNode)
			if instr == nil {
				continue
			}

			sn := sourceNode(node.GraphNode)
			if isSourceNode(cfg, sn) {
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

	return positions
}

func isSourceNode(cfg *config.Config, source ssa.Node) bool {
	if node, ok := source.(*ssa.Call); ok {
		if node == nil {
			return false
		}

		// most of this logic is from analysisutil.IsEntrypointNode
		if node.Call.IsInvoke() {
			receiver := node.Call.Value.Name()
			methodName := node.Call.Method.Name()
			calleePkg := analysisutil.FindSafeCalleePkg(node.Common())
			if calleePkg.IsSome() {
				return config.Config.IsSomeSource(*cfg,
					config.CodeIdentifier{Package: calleePkg.Value(), Method: methodName, Receiver: receiver})
			} else {
				// HACK this is needed because "invoked" functions sometimes don't have a callee package
				return config.Config.IsSomeSource(*cfg,
					config.CodeIdentifier{Package: "command-line-arguments", Method: methodName, Receiver: receiver})
			}
		}
	}

	return taint.IsSomeSourceNode(cfg, nil, source)
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
