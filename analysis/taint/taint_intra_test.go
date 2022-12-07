package taint

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/ssa"
)

func loadTest(t *testing.T, dir string, extraFiles []string) (*ssa.Program, *config.Config) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	// Load config; in command, should be set using some flag
	configFile := filepath.Join(testdata, "src", dir, "config.yaml")
	config.SetGlobalConfig(configFile)
	if err != nil {
		t.Errorf("could not set config file: %v", err)
	}

	files := []string{filepath.Join(testdata, "src", dir, "main.go")}
	for _, extraFile := range extraFiles {
		files = append(files, filepath.Join(testdata, "src", dir, extraFile))
	}

	pkgs, err := analysis.LoadProgram(nil, "", ssa.BuilderMode(0), files)
	if err != nil {
		t.Fatalf("error loading packages.")
	}
	cfg, err := config.LoadGlobal()
	if err != nil {
		t.Fatalf("error loading global config.")
	}
	return pkgs, cfg
}

func TestIntraprocedural(t *testing.T) {
	var err error

	pkgs, cfg := loadTest(t, "taint-tracking-intra", []string{})

	result, err := Analyze(log.Default(), cfg, pkgs)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expected := map[int]map[int]bool{
		53:  {50: true},
		56:  {50: true},
		58:  {57: true},
		70:  {66: true},
		81:  {77: true},
		94:  {89: true},
		105: {99: true},
		120: {117: true},
		137: {139: true},
		126: {124: true},
		129: {127: true},
		154: {153: true},
		165: {164: true},
		171: {170: true},
		185: {183: true},
		193: {192: true},
		195: {192: true},
		207: {205: true},
		257: {252: true},
		255: {252: true}, // TODO: see #3
		264: {261: true, 262: true},
		275: {270: true, 272: true},
		295: {283: true, 286: true, 288: true},
		// Flows to return nodes
		237: {233: true},
		242: {233: true},
	}

	for sink, sources := range ReachedSinkPositions(pkgs, result.TaintFlows) {
		for source := range sources {
			if expectedSource, ok := expected[sink.Line]; ok && expectedSource[source.Line] {
				delete(expectedSource, source.Line)
			} else {
				t.Errorf("ERROR in main.go: false positive: %d flows to %d\n", source.Line, sink.Line)
			}
		}
	}

	for sinkLine, sources := range expected {
		for sourceLine := range sources {
			// Remaining entries have not been detected!
			t.Errorf("ERROR in main.go: failed to detect that %d flows to %d\n", sourceLine, sinkLine)
		}
	}
}
