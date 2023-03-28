//go:build go1.20

package dataflow_test

import (
	"path"
	"runtime"
	"testing"

	df "github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/utils"
	"golang.org/x/tools/go/ssa"
)

func TestComputeMethodImplementationsGo120(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/dataflow/callgraph")
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
		"(*io.OffsetWriter).Write":          true, // new in 1.20
	})
}
