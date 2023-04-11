package taint

import (
	"testing"
)

func TestCrossFunctionExample0(t *testing.T) {
	runTest(t, "example0", []string{})
}

func TestCrossFunctionIntra(t *testing.T) {
	runTest(t, "single-function", []string{})
}

func TestCrossFunctionBasic(t *testing.T) {
	runTest(t, "basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go",
		"sanitizers.go"})
}

func TestCrossFunctionBuiltins(t *testing.T) {
	runTest(t, "builtins", []string{"helpers.go"})
}

func TestCrossFunctionInterfaces(t *testing.T) {
	runTest(t, "interfaces", []string{})
}

func TestCrossFunctionParameters(t *testing.T) {
	runTest(t, "parameters", []string{})
}

func TestCrossFunctionExample1(t *testing.T) {
	runTest(t, "example1", []string{})
}

func TestCrossFunctionExample2(t *testing.T) {
	runTest(t, "example2", []string{})
}

func TestCrossFunctionDefers(t *testing.T) {
	runTest(t, "defers", []string{})
}

func TestCrossFunctionClosures(t *testing.T) {
	runTest(t, "closures", []string{"helpers.go"})
}

func TestCrossFunctionInterfaceSummaries(t *testing.T) {
	runTest(t, "interface-summaries", []string{"helpers.go"})
}

func TestCrossFunctionSanitizers(t *testing.T) {
	runTest(t, "sanitizers", []string{})
}

func TestCrossFunctionValidators(t *testing.T) {
	runTest(t, "validators", []string{})
}

func TestCrossFunctionExamplesFromLevee(t *testing.T) {
	runTest(t, "fromlevee", []string{})
}

func TestCrossFunctionGlobals(t *testing.T) {
	runTest(t, "globals", []string{"helpers.go"})
}

func TestCrossFunctionStdlib(t *testing.T) {
	runTest(t, "stdlib", []string{"helpers.go"})
}

func TestCrossFunctionSelects(t *testing.T) {
	runTest(t, "selects", []string{"helpers.go"})
}

func TestCrossFunctionTuples(t *testing.T) {
	runTest(t, "tuples", []string{})
}

func TestCrossFunctionPanics(t *testing.T) {
	runTest(t, "panics", []string{})
}

func TestCrossFunctionFilters(t *testing.T) {
	runTest(t, "filters", []string{})
}
