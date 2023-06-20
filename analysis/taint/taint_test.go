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
	runTest(t, "example0", []string{})
}

func TestCrossFunctionExample0_SummarizeOnDemand(t *testing.T) {
	t.Skipf("Example 0 has a false positive in the tests")
	runTestSummarizeOnDemand(t, "example0", []string{})
}

func TestCrossFunctionIntra(t *testing.T) {
	runTest(t, "single-function", []string{})
}

func TestCrossFunctionIntra_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "single-function", []string{})
}

func TestCrossFunctionBasic(t *testing.T) {
	runTest(t, "basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go",
		"sanitizers.go", "memory.go"})
}

func TestCrossFunctionBasic_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go",
		"sanitizers.go", "memory.go"})
}

func TestCrossFunctionBuiltins(t *testing.T) {
	runTest(t, "builtins", []string{"helpers.go"})
}

func TestCrossFunctionBuiltins_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "builtins", []string{"helpers.go"})
}

func TestCrossFunctionInterfaces(t *testing.T) {
	runTest(t, "interfaces", []string{})
}

func TestCrossFunctionInterfaces_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "interfaces", []string{})
}

func TestCrossFunctionParameters(t *testing.T) {
	runTest(t, "parameters", []string{})
}

func TestCrossFunctionParameters_SummarizeOnDemand(t *testing.T) {
	t.Skipf("skipping until fixed")
	runTestSummarizeOnDemand(t, "parameters", []string{})
}

func TestCrossFunctionExample1(t *testing.T) {
	runTest(t, "example1", []string{})
}

func TestCrossFunctionExample1_SummarizeOnDemand(t *testing.T) {
	t.Skipf("skipping until fixed")
	runTestSummarizeOnDemand(t, "example1", []string{})
}

func TestCrossFunctionExample2(t *testing.T) {
	runTest(t, "example2", []string{})
}

func TestCrossFunctionExample2_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "example2", []string{})
}

func TestCrossFunctionDefers(t *testing.T) {
	runTest(t, "defers", []string{})
}

func TestCrossFunctionDefers_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "defers", []string{})
}

func TestCrossFunctionClosures(t *testing.T) {
	runTest(t, "closures", []string{"helpers.go"})
}

func TestCrossFunctionClosures_SummarizeOnDemand(t *testing.T) {
	t.Skipf("Skipping until fixed.")
	runTestSummarizeOnDemand(t, "closures", []string{"helpers.go"})
}

func TestCrossFunctionInterfaceSummaries(t *testing.T) {
	runTest(t, "interface-summaries", []string{"helpers.go"})
}

func TestCrossFunctionInterfaceSummaries_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "interface-summaries", []string{"helpers.go"})
}

func TestCrossFunctionSanitizers(t *testing.T) {
	runTest(t, "sanitizers", []string{})
}

func TestCrossFunctionSanitizers_SummarizeOnDemand(t *testing.T) {
	t.Skipf("skipping until fixed")
	runTestSummarizeOnDemand(t, "sanitizers", []string{})
}

func TestCrossFunctionValidators(t *testing.T) {
	runTest(t, "validators", []string{"values.go"})
}

func TestCrossFunctionValidators_SummarizeOnDemand(t *testing.T) {
	t.Skipf("skipping until fixed")
	runTestSummarizeOnDemand(t, "validators", []string{"values.go"})
}

func TestCrossFunctionExamplesFromLevee(t *testing.T) {
	runTest(t, "fromlevee", []string{})
}

func TestCrossFunctionExamplesFromLevee_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "fromlevee", []string{})
}

func TestCrossFunctionGlobals(t *testing.T) {
	runTest(t, "globals", []string{"helpers.go"})
}

func TestCrossFunctionGlobals_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "globals", []string{"helpers.go"})
}

func TestCrossFunctionStdlib(t *testing.T) {
	runTest(t, "stdlib", []string{"helpers.go"})
}

func TestCrossFunctionStdlib_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "stdlib", []string{"helpers.go"})
}

func TestCrossFunctionSelects(t *testing.T) {
	runTest(t, "selects", []string{"helpers.go"})
}

func TestCrossFunctionSelects_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "selects", []string{"helpers.go"})
}

func TestCrossFunctionTuples(t *testing.T) {
	runTest(t, "tuples", []string{})
}

func TestCrossFunctionTuples_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "tuples", []string{})
}

func TestCrossFunctionPanics(t *testing.T) {
	runTest(t, "panics", []string{})
}

func TestCrossFunctionPanics_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "panics", []string{})
}

func TestCrossFunctionFilters(t *testing.T) {
	runTest(t, "filters", []string{})
}

func TestCrossFunctionFilters_SummarizeOnDemand(t *testing.T) {
	runTestSummarizeOnDemand(t, "filters", []string{})
}

func TestEscapeIntegration(t *testing.T) {
	runTest(t, "escape-integration", []string{})
}
