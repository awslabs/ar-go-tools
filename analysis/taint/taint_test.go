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
	"embed"
	"testing"
)

// NOTE go:embed does not include any directories with go.mod files.
// It also does not allow embedding files outside the current directory
// which is why the testdata directory is located here.

//go:embed testdata
var testfsys embed.FS

func TestTaint(t *testing.T) {
	t.Parallel()
	type args struct {
		dirName     string
		extraFiles  []string
		expectError func(error) bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "example 0",
			args: args{"example0", []string{}, noErrorExpected},
		},
		{
			name: "intra-procedural",
			args: args{"intra-procedural", []string{}, noErrorExpected},
		},
		{
			name: "basic",
			args: args{
				"basic",
				[]string{
					"bar.go",
					"example.go",
					"example2.go",
					"example3.go",
					"fields.go",
					"sanitizers.go",
					"memory.go",
					"channels.go",
				},
				noErrorExpected,
			},
		},
		{
			name: "builtins",
			args: args{"builtins", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "stdlib",
			args: args{"stdlib", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "stdlib with no-effect constraints",
			args: args{"stdlib-no-effect-constraint", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "selects",
			args: args{"selects", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "tuples",
			args: args{"tuples", []string{}, noErrorExpected},
		},
		{
			name: "panics",
			args: args{"panics", []string{}, noErrorExpected},
		},
		{
			name: "interfaces",
			args: args{"interfaces", []string{}, noErrorExpected},
		},
		{
			name: "interfaces with summaries",
			args: args{"interface-summaries", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "parameters",
			args: args{"parameters", []string{}, noErrorExpected},
		},
		{
			name: "example1",
			args: args{
				"example1",
				[]string{},
				expectTaintedCondInFuncs("source"),
			},
		},
		{
			name: "example2",
			args: args{
				"example2",
				[]string{},
				expectTaintedCondInFuncs("rec", "extract", "main"),
			},
		},
		{
			name: "closures",
			args: args{"closures", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "closures (precise flow)",
			args: args{"closures_flowprecise", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "closures (from paper)",
			args: args{"closures_paper", []string{"helpers.go"}, noErrorExpected},
		},
		{
			name: "defers",
			args: args{"defers", []string{}, noErrorExpected},
		},
		{
			name: "sanitizers",
			args: args{"sanitizers", []string{}, noErrorExpected},
		},
		{
			name: "validators",
			args: args{
				"validators",
				[]string{"values.go"},
				expectTaintedCondInFuncs("validatorExample4", "Validate2"),
			},
		},
		{
			name: "taint with filters",
			args: args{"filters", []string{}, noErrorExpected},
		},
		{
			name: "sources with context",
			args: args{"with-context", []string{}, noErrorExpected},
		},
		{
			name: "with field sensitivity",
			args: args{"fields", []string{}, noErrorExpected},
		},
		{
			name: "fromlevee",
			args: args{
				"fromlevee",
				[]string{},
				expectTaintedCondInFuncs(
					"TestRangeOverMapWithSourceAsKey",
					"TestRangeOverMapWithSourceAsValue",
					"TestSinkAfterTaintInFor",
					"TestRangeOverChan",
					"TestRangeOverSlice",
					"TestRangeOverInterfaceSlice",
				),
			},
		},
		{
			name: "globals",
			args: args{"globals", []string{"helpers.go", "foo/foo.go"}, noErrorExpected},
		},
		{
			name: "complex functionality example",
			args: args{
				"agent-example",
				[]string{},
				noErrorExpected, // config specifies explicit flow only
			},
		},
		{
			name: "implicit flow",
			args: args{
				"implicit-flow",
				[]string{},
				expectTaintedCondInFuncs("example1", "example2", "example3", "switchByte"),
			},
		},
		{
			name: "annotations",
			args: args{"annotations", []string{}, noErrorExpected},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runTest(t, tt.args.dirName, tt.args.extraFiles, false, tt.args.expectError)
		})
		t.Run(tt.name+"-on-demand", func(t *testing.T) {
			t.Parallel()
			runTest(t, tt.args.dirName, tt.args.extraFiles, true, tt.args.expectError)
		})
	}
}

func TestPlayground(t *testing.T) {
	t.Parallel()
	runTest(t, "playground", []string{}, false, noErrorExpected)
}

func TestBenchmark(t *testing.T) {
	t.Parallel()
	t.Run("benchmark", func(t *testing.T) {
		t.Parallel()
		runTestWithoutCheck(t, "benchmark", []string{}, false, noErrorExpected)
	})
	t.Run("benchmark-on-demand", func(t *testing.T) {
		t.Parallel()
		runTestWithoutCheck(t, "benchmark", []string{}, true, noErrorExpected)
	})
}
