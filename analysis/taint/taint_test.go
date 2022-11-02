package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestAll(t *testing.T) {
	var err error
	// Paths
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	// Load config; in command, should be set using some flag
	configFile := filepath.Join(testdata, "src/taint-tracking/config.yaml")
	config.SetGlobalConfig(configFile)
	if err != nil {
		t.Errorf("could not set config file: %v", err)
	}
	pkgLoadConfig := &packages.Config{
		Mode:  PkgLoadMode,
		Tests: false,
	}
	pkgs, err := analysis.LoadProgram(pkgLoadConfig, ssa.BuilderMode(0),
		[]string{filepath.Join(testdata, "src/taint-tracking/main.go")})
	if err != nil {
		t.Fatalf("error loading packages.")
	}
	cfg, err := config.LoadGlobal()
	if err != nil {
		t.Fatalf("error loading global config.")
	}
	ttInfo, err := Analyze(log.Default(), cfg, pkgs)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}

	expected := map[int]int{
		53:  50,
		56:  50,
		58:  57,
		70:  66,
		81:  77,
		94:  89,
		105: 99,
		120: 117,
		137: 139,
		126: 124,
		129: 127,
		154: 153,
		165: 164,
		171: 170,
		185: 183,
		193: 192,
		195: 192,
		207: 205,
		257: 252,
		255: 252, // TODO: better path analysis
		// Flows to return nodes
		28:  28,
		221: 218,
		237: 233,
		242: 233,
		245: 233,
	}

	for sink, source := range ttInfo.ReachedSinkPositions(pkgs) {
		if expectedSource, ok := expected[sink.Line]; ok && expectedSource == source.Line {
			delete(expected, sink.Line)
		} else {
			t.Errorf("ERROR in main.go: false positive: %d flows to %d\n", source.Line, sink.Line)
		}
	}
	for sinkLine, sourceLine := range expected {
		// Remaining entries have not been detected!
		t.Errorf("ERROR in main.go: failed to detect that %d flows to %d\n", sourceLine, sinkLine)
	}
}
