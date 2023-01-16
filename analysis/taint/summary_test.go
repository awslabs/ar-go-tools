package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/utils"
	"log"
	"path"
	"runtime"
	"testing"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
)

func TestFunctionSummaries(t *testing.T) {
	var err error
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/summaries")
	// Loading the program for testdata/src/taint-tracking-summaries/main.go
	program, cfg := utils.LoadTest(t, dir, []string{})
	result, err := Analyze(log.Default(), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	for function, summary := range result.Graph.Summaries {

		if function.Name() == "main" {
			ok := len(summary.Returns) == 1
			ok = ok && len(summary.Params) == 0
			ok = ok && len(summary.Callees) == 5
			if !ok {
				t.Errorf("main graph is not as expected")
			}
		}

		if function.Name() == "Bar" {
			ok := len(summary.Returns) == 1
			ok = ok && len(summary.Params) == 1
			ok = ok && len(summary.Callees) == 1
			if !ok {
				t.Errorf("Bar graph is not as expected")
			}
			for _, argNode := range summary.Params {
				ok = len(argNode.Out()) == 2
				for dest := range argNode.Out() {
					_, isCallNodeArg := dest.(*dataflow.CallNodeArg)
					_, isReturnNode := dest.(*dataflow.ReturnNode)
					ok = ok && (isCallNodeArg || isReturnNode)
				}
				if !ok {
					t.Errorf("Bar argument should only have two outgoing edges to a function call argument")
				}
			}

		}

		if function.Name() == "Foo" {
			ok := len(summary.Returns) == 1
			ok = ok && len(summary.Params) == 3
			ok = ok && len(summary.Callees) == 2
			if !ok {
				t.Errorf("Foo graph is not as expected")
			}
			for _, argNode := range summary.Params {
				if argNode.SsaNode().Name() == "s" {
					ok = len(argNode.Out()) == 1
					if !ok {
						t.Errorf("in Foo, s should have one outgoing edge")
					}
				}
				if argNode.SsaNode().Name() == "s2" {
					ok = len(argNode.Out()) == 1
					if !ok {
						t.Errorf("in Foo, s should have one outgoing edge")
					}
				}
			}
		}

		if function.Name() == "FooBar" {
			ok := len(summary.Returns) == 1
			ok = ok && len(summary.SyntheticNodes) == 2
			if !ok {
				t.Errorf("FooBar graph is not as expected")
			}
		}
	}
}
