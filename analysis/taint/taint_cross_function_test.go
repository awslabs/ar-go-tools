package taint

import (
	"log"
	"os"
	"path"
	"runtime"
	"testing"
)

func runTest(t *testing.T, dirName string, files []string) {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/cross-function/", dirName)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	// The loadTest function is relative to the testdata/src/taint-tracking-inter folder so we can load an entire
	// module with subpackages
	program, cfg := loadTest(t, ".", files)

	result, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expected := getExpectedSourceToSink(dir, ".")
	checkExpectedPositions(t, program, result.TaintFlows, expected)
}

func TestCrossFunctionBasic(t *testing.T) {
	runTest(t, "basic", []string{"bar.go", "example.go", "example2.go", "example3.go", "fields.go"})
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
