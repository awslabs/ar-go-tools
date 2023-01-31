package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/utils"
	"log"
	"path"
	"runtime"
	"testing"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

func checkExpected(t *testing.T, program *ssa.Program, taintFlows dataflow.DataFlows, expected map[int]map[int]bool) {
	for sink, sources := range dataflow.ReachedSinkPositions(program, taintFlows) {
		for source := range sources {
			if _, ok := expected[sink.Line]; ok && expected[sink.Line][source.Line] {
				delete(expected[sink.Line], source.Line)
			} else {
				t.Errorf("ERROR in main.go: false positive: %d flows to %d\n", source.Line, sink.Line)
			}
		}
	}

	for sinkLine, sources := range expected {
		for sourceLine := range sources {
			// Remaining entries have not been detected!
			t.Errorf("ERROR in main.go: failed to detect that %d:0 flows to %d:0\n", sourceLine, sinkLine)
		}
	}
}

func TestSingleFunction(t *testing.T) {
	var err error
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/single-function")
	pkgs, cfg := utils.LoadTest(t, dir, []string{})

	result, err := Analyze(log.Default(), cfg, pkgs)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expected := map[int]map[int]bool{
		53:  {50: true},
		56:  {50: true},
		58:  {57: true},
		70:  {66: true},
		81:  {77: true},
		94:  {89: true},
		105: {99: true},
		120: {117: true},
		137: {139: true},
		126: {124: true},
		129: {127: true},
		154: {153: true},
		165: {164: true},
		171: {170: true},
		185: {183: true},
		193: {192: true},
		195: {192: true},
		207: {205: true},
		257: {252: true},
		255: {252: true},
		264: {261: true, 262: true},
		275: {270: true, 272: true},
		295: {283: true, 286: true, 288: true},
		// Flows to return nodes
		237: {233: true},
		242: {233: true},
	}

	checkExpected(t, pkgs, result.TaintFlows, expected)
}
