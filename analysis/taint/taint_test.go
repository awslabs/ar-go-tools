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

package taint

import (
	"testing"
)

func TestCrossFunctionExample0(t *testing.T) {
	runTest(t, "example0", []string{}, false, noErrorExpected)
}

func TestCrossFunctionExample0_SummarizeOnDemand(t *testing.T) {
	runTest(t, "example0", []string{}, true, noErrorExpected)
}

func TestCrossFunctionIntra(t *testing.T) {
	runTest(t, "intra-procedural", []string{}, false, noErrorExpected)
}

func TestCrossFunctionIntra_SummarizeOnDemand(t *testing.T) {
	runTest(t, "intra-procedural", []string{}, true, noErrorExpected)
}

func TestCrossFunctionBasic(t *testing.T) {
	runTest(t, "basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go",
		"sanitizers.go", "memory.go", "channels.go"}, false, noErrorExpected)
}

func TestCrossFunctionBasic_SummarizeOnDemand(t *testing.T) {
	runTest(t, "basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go",
		"sanitizers.go", "memory.go", "channels.go"}, true, noErrorExpected)
}

func TestCrossFunctionBuiltins(t *testing.T) {
	runTest(t, "builtins", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionBuiltins_SummarizeOnDemand(t *testing.T) {
	runTest(t, "builtins", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionInterfaces(t *testing.T) {
	runTest(t, "interfaces", []string{}, false, noErrorExpected)
}

func TestCrossFunctionInterfaces_SummarizeOnDemand(t *testing.T) {
	runTest(t, "interfaces", []string{}, true, noErrorExpected)
}

func TestCrossFunctionParameters(t *testing.T) {
	runTest(t, "parameters", []string{}, false, noErrorExpected)
}

func TestCrossFunctionParameters_SummarizeOnDemand(t *testing.T) {
	runTest(t, "parameters", []string{}, true, noErrorExpected)
}

func TestCrossFunctionExample1(t *testing.T) {
	runTest(t, "example1", []string{}, false, noErrorExpected)
}

func TestCrossFunctionExample1_SummarizeOnDemand(t *testing.T) {
	runTest(t, "example1", []string{}, true, noErrorExpected)
}

func TestCrossFunctionExample2(t *testing.T) {
	runTest(t, "example2", []string{}, false, noErrorExpected)
}

func TestCrossFunctionExample2_SummarizeOnDemand(t *testing.T) {
	runTest(t, "example2", []string{}, true, noErrorExpected)
}

func TestCrossFunctionDefers(t *testing.T) {
	runTest(t, "defers", []string{}, false, noErrorExpected)
}

func TestCrossFunctionDefers_SummarizeOnDemand(t *testing.T) {
	runTest(t, "defers", []string{}, true, noErrorExpected)
}

func TestCrossFunctionClosures(t *testing.T) {
	runTest(t, "closures", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionClosures_SummarizeOnDemand(t *testing.T) {
	runTest(t, "closures", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionClosuresFlowPrecise(t *testing.T) {
	runTest(t, "closures_flowprecise", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionClosuresFlowPrecise_SummarizeOnDemand(t *testing.T) {
	runTest(t, "closures_flowprecise", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionClosuresPaper(t *testing.T) {
	runTest(t, "closures_paper", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionClosuresPaper_SummarizeOnDemand(t *testing.T) {
	runTest(t, "closures_paper", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionInterfaceSummaries(t *testing.T) {
	runTest(t, "interface-summaries", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionInterfaceSummaries_SummarizeOnDemand(t *testing.T) {
	runTest(t, "interface-summaries", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionSanitizers(t *testing.T) {
	runTest(t, "sanitizers", []string{}, false, noErrorExpected)
}

func TestCrossFunctionSanitizers_SummarizeOnDemand(t *testing.T) {
	runTest(t, "sanitizers", []string{}, true, noErrorExpected)
}

func TestCrossFunctionValidators(t *testing.T) {
	runTest(t, "validators", []string{"values.go"}, false, noErrorExpected)
}

func TestCrossFunctionValidators_SummarizeOnDemand(t *testing.T) {
	runTest(t, "validators", []string{"values.go"}, true, noErrorExpected)
}

func TestCrossFunctionExamplesFromLevee(t *testing.T) {
	runTest(t, "fromlevee", []string{}, false, noErrorExpected)
}

func TestCrossFunctionExamplesFromLevee_SummarizeOnDemand(t *testing.T) {
	runTest(t, "fromlevee", []string{}, true, noErrorExpected)
}

func TestCrossFunctionGlobals(t *testing.T) {
	runTest(t, "globals", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionGlobals_SummarizeOnDemand(t *testing.T) {
	runTest(t, "globals", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionStdlib(t *testing.T) {
	runTest(t, "stdlib", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionStdlib_SummarizeOnDemand(t *testing.T) {
	runTest(t, "stdlib", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionSelects(t *testing.T) {
	runTest(t, "selects", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionSelects_SummarizeOnDemand(t *testing.T) {
	runTest(t, "selects", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionTuples(t *testing.T) {
	runTest(t, "tuples", []string{}, false, noErrorExpected)
}

func TestCrossFunctionTuples_SummarizeOnDemand(t *testing.T) {
	runTest(t, "tuples", []string{}, true, noErrorExpected)
}

func TestCrossFunctionPanics(t *testing.T) {
	runTest(t, "panics", []string{}, false, noErrorExpected)
}

func TestCrossFunctionPanics_SummarizeOnDemand(t *testing.T) {
	runTest(t, "panics", []string{}, true, noErrorExpected)
}

func TestCrossFunctionFilters(t *testing.T) {
	runTest(t, "filters", []string{}, false, noErrorExpected)
}

func TestCrossFunctionFilters_SummarizeOnDemand(t *testing.T) {
	runTest(t, "filters", []string{}, true, noErrorExpected)
}

func TestComplexExample(t *testing.T) {
	runTest(t, "agent-example", []string{}, false, noErrorExpected)
}

func TestCrossFunctionWithContext(t *testing.T) {
	runTest(t, "with-context", []string{}, false, noErrorExpected)
}

func TestCrossFunctionWithContext_SummarizeOnDemand(t *testing.T) {
	runTest(t, "with-context", []string{}, true, noErrorExpected)
}

func TestField(t *testing.T) {
	runTest(t, "fields", []string{}, false, noErrorExpected)
}

func TestBenchmark(t *testing.T) {
	runTest(t, "benchmark", []string{}, false, noErrorExpected)
}

func TestPlayground(t *testing.T) {
	runTest(t, "playground", []string{}, false, noErrorExpected)
}

func TestCapabilities(t *testing.T) {
	runTest(t, "capabilities", []string{}, false, noErrorExpected)
}
