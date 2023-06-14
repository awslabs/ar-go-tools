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

//go:build !go1.19

package dataflow_test

import (
	"path"
	"runtime"
	"testing"

	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/testutils"
	"golang.org/x/tools/go/ssa"
)

func TestComputeMethodImplementations(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/dataflow/callgraph")
	program, _ := testutils.LoadTest(t, dir, []string{})
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
