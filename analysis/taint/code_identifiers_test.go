package taint

import (
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/argot/analysis/config"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
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
				pos := (instruction).Pos() // getting the position with this should be ok for callees and rvalues
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
	// TaintFlows
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	// Load config; in command, should be set using some flag
	configFile := filepath.Join(testdata, "src/taint/sources/config.yaml")
	config.SetGlobalConfig(configFile)
	if err != nil {
		t.Errorf("could not set config file: %v", err)
	}
	analysistest.Run(t, testdata, taintSourcesAnalyzer, "taint/sources")
}

// For testing purposes only: an analyzer that identifies where sources are
// Wrap the source identification into an analysis pass for testing purposes
var taintSinksAnalyzer = &analysis.Analyzer{
	Name:     "taint-sinks",
	Doc:      "Reports taint sinks in Go code for testing.",
	Run:      runSinkAnalysis,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

func runSinkAnalysis(pass *analysis.Pass) (interface{}, error) {
	testConfig, err := config.LoadGlobal()
	if err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}
	ssaInfo := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	sourceMap := NewSinkMap(testConfig, []*ssa.Package{ssaInfo.Pkg})
	for _, fnMap := range sourceMap {
		for _, instrs := range fnMap {
			for _, instruction := range instrs {
				pos := (instruction).Pos() // getting the position with this should be ok for callees and rvalues
				if pos != token.NoPos {
					pass.Reportf(pos, "found a sink")
				}
			}
		}
	}
	return nil, nil
}

func TestAllSinks(t *testing.T) {
	var err error
	// TaintFlows
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testdata")
	// Load config
	configFile := filepath.Join(testdata, "src/taint/sinks/config.yaml")
	config.SetGlobalConfig(configFile)
	if err != nil {
		t.Errorf("could not set config file: %v", err)
	}
	analysistest.Run(t, testdata, taintSinksAnalyzer, "taint/sinks")
}
