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

//go:build go1.23

package dataflow_test

import (
	"path/filepath"
	"testing"

	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"golang.org/x/tools/go/ssa"
)

func TestComputeMethodImplementationsGo123(t *testing.T) {
	dir := filepath.Join("testdata", "callgraph")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	program := lp.Program
	implementations := map[string]map[*ssa.Function]bool{}
	contracts := map[string]*df.SummaryGraph{}
	keys := map[string]string{}
	if err := df.ComputeMethodImplementations(program, implementations, contracts, keys); err != nil {
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
		"(*command-line-arguments.B).Write":       true,
		"(*fmt.pp).Write":                         true,
		"(*io.multiWriter).Write":                 true,
		"(*os.File).Write":                        true,
		"(*io.discard).Write":                     true,
		"(*internal/poll.FD).Write":               true,
		"(*os.fileWithoutReadFrom).Write":         true, // new in 1.21
		"(os.fileWithoutReadFrom).Write":          true, // new in 1.21
		"(os.fileWithoutWriteTo).Write":           true, // new in 1.22
		"(*os.fileWithoutWriteTo).Write":          true, // new in 1.22
		"(*internal/godebug.runtimeStderr).Write": true, // new in 1.23
	})
}
