package taint

import (
	"log"
	"path"
	"runtime"
	"testing"
)

func TestFunctionSummaries(t *testing.T) {
	var err error
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/summaries")
	// Loading the program for testdata/src/taint-tracking-summaries/main.go
	program, cfg := loadTest(t, dir, []string{})
	result, err := Analyze(log.Default(), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	for function, summary := range result.Graph.summaries {

		if function.Name() == "main" {
			ok := len(summary.returns) == 1
			ok = ok && len(summary.params) == 0
			ok = ok && len(summary.callees) == 5
			if !ok {
				t.Errorf("main graph is not as expected")
			}
		}

		if function.Name() == "Bar" {
			ok := len(summary.returns) == 1
			ok = ok && len(summary.params) == 1
			ok = ok && len(summary.callees) == 1
			if !ok {
				t.Errorf("Bar graph is not as expected")
			}
			for _, argNode := range summary.params {
				ok = len(argNode.Out()) == 2
				for dest := range argNode.Out() {
					_, isCallNodeArg := dest.(*CallNodeArg)
					_, isReturnNode := dest.(*ReturnNode)
					ok = ok && (isCallNodeArg || isReturnNode)
				}
				if !ok {
					t.Errorf("Bar argument should only have two outgoing edges to a function call argument")
				}
			}

		}

		if function.Name() == "Foo" {
			ok := len(summary.returns) == 1
			ok = ok && len(summary.params) == 3
			ok = ok && len(summary.callees) == 2
			if !ok {
				t.Errorf("Foo graph is not as expected")
			}
			for _, argNode := range summary.params {
				if argNode.ssaNode.Name() == "s" {
					ok = len(argNode.out) == 1
					if !ok {
						t.Errorf("in Foo, s should have one outgoing edge")
					}
				}
				if argNode.ssaNode.Name() == "s2" {
					ok = len(argNode.out) == 1
					if !ok {
						t.Errorf("in Foo, s should have one outgoing edge")
					}
				}
			}
		}

		if function.Name() == "FooBar" {
			ok := len(summary.returns) == 1
			ok = ok && len(summary.syntheticNodes) == 2
			if !ok {
				t.Errorf("FooBar graph is not as expected")
			}
		}

	}

}
