package taint

import (
	"log"
	"os"
	"testing"
)

func TestInterprocedural(t *testing.T) {
	var err error

	program, cfg := loadTest(t, "taint-tracking-inter", []string{"bar.go", "example.go", "example2.go"})

	result, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expected := map[int]map[int]bool{
		34: {6: true},  // in main.go
		23: {14: true}, // in bar.go
		18: {14: true}, // in example.go
		45: {32: true}, // in example.go
		22: {21: true}, // in example2.go
		27: {21: true}, // in example2.go
	}

	for sink, sources := range ReachedSinkPositions(program, result.TaintFlows) {
		for source := range sources {
			if expectedSource, ok := expected[sink.Line]; ok && expectedSource[source.Line] {
				delete(expectedSource, source.Line)
			} else {
				t.Errorf("ERROR in main.go: false positive: %d flows to %d\n", source.Line, sink.Line)
			}
		}
	}

	for sinkLine, sources := range expected {
		for sourceLine := range sources {
			// Remaining entries have not been detected!
			t.Errorf("ERROR in main.go: failed to detect that %d flows to %d\n", sourceLine, sinkLine)
		}
	}
}
