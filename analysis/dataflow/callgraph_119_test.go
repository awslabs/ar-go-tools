//go:build !go1.19

package dataflow_test

import (
	"path"
	"runtime"
	"testing"

	df "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/utils"
	"golang.org/x/tools/go/ssa"
)

func TestComputeMethodImplementations(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/dataflow")
	program, _ := utils.LoadTest(t, dir, []string{})
	implementations := map[string]map[*ssa.Function]bool{}
	contracts := map[string]*df.SummaryGraph{}
	keys := map[string]string{}
	err := df.ComputeMethodImplementations(program, implementations, contracts, keys)
	if err != nil {
		t.Fatalf("Error computing method implementations: %s", err)
	}
	methodTest(t, implementations, "command-line-arguments.I.f", map[string]bool{
		"(*command-line-arguments.A).f": true,
		"(*command-line-arguments.B).f": true,
	})
	methodTest(t, implementations, "command-line-arguments.I.g", map[string]bool{
		"(*command-line-arguments.A).g": true,
		"(*command-line-arguments.B).g": true,
	})
	methodTest(t, implementations, "command-line-arguments.J.h", map[string]bool{
		"(*command-line-arguments.B).h": true,
	})
	// Test that standard library implementations are recorded
	methodTest(t, implementations, "io.Writer.Write", map[string]bool{
		"(*command-line-arguments.B).Write": true,
		"(*fmt.pp).Write":                   true,
		"(*io.multiWriter).Write":           true,
		"(*os.File).Write":                  true,
		"(*os.onlyWriter).Write":            true,
		"(*io.discard).Write":               true,
		"(*internal/poll.FD).Write":         true,
		"(os.onlyWriter).Write":             true,
		"(*io.PipeWriter).Write":            true,
	})
}
