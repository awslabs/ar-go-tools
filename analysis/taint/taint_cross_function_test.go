package taint

import (
	"testing"
)

func TestCrossFunctionBasic(t *testing.T) {
	runTest(t, "basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go",
		"sanitizers.go"})
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

func TestCrossFunctionExamplesFromLevee(t *testing.T) {
	runTest(t, "fromlevee", []string{})
}

func TestCrossFunctionGlobals(t *testing.T) {
	runTest(t, "globals", []string{"helpers.go"})
}