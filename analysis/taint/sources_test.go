package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"go/token"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
	"os"
	"path/filepath"
	"testing"
)

// For testing purposes only: an analyzer that identifies where sources are
// Wrap the source identification into an analysis pass for testing purposes
var taintSourcesAnalyzer = &analysis.Analyzer{
	Name:     "taint-sources",
	Doc:      "Reports taint sources in Go code for testing.",
	Run:      runSourcesAnalysis,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

func runSourcesAnalysis(pass *analysis.Pass) (interface{}, error) {
	testConfig, err := config.LoadGlobal()
	if err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}
	ssaInfo := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	sourceMap := NewSourceMap(testConfig, []*ssa.Package{ssaInfo.Pkg})
	for _, fnMap := range sourceMap {
		for _, instructions := range fnMap {
			for _, instruction := range instructions {
				pos := (instruction).Pos() // getting the position with this should be ok for calls and rvalues
				if pos != token.NoPos {
					pass.Reportf(pos, "found a source")
				}
			}
		}
	}
	return nil, nil
}

func TestAllSources(t *testing.T) {
	var err error
	// Paths
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	// Load config; in command, should be set using some flag
	configFile := filepath.Join(testdata, "src/taint-sources/config.yaml")
	config.SetGlobalConfig(configFile)
	if err != nil {
		t.Errorf("could not set config file: %v", err)
	}
	analysistest.Run(t, testdata, taintSourcesAnalyzer, "taint-sources", "bar")
}
