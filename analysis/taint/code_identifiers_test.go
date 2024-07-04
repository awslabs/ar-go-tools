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
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

type functionToNode map[*ssa.Function][]ssa.Node

type PackageToNodes map[*ssa.Package]functionToNode

type nodeIDFunction func(*dataflow.AnalyzerState, ssa.Node) bool

func NewPackagesMap(s *dataflow.AnalyzerState, f nodeIDFunction) PackageToNodes {
	packageMap := make(PackageToNodes)
	for _, pkg := range s.Program.AllPackages() {
		pkgMap := newPackageMap(s, pkg, f)
		if len(pkgMap) > 0 {
			packageMap[pkg] = pkgMap
		}
	}
	return packageMap
}

func newPackageMap(s *dataflow.AnalyzerState, pkg *ssa.Package, f nodeIDFunction) functionToNode {
	fMap := make(functionToNode)
	for _, mem := range pkg.Members {
		switch fn := mem.(type) {
		case *ssa.Function:
			populateFunctionMap(s, fMap, fn, f)
		}
	}
	return fMap
}

func populateFunctionMap(s *dataflow.AnalyzerState, fMap functionToNode, current *ssa.Function, f nodeIDFunction) {
	var sources []ssa.Node
	for _, b := range current.Blocks {
		for _, instr := range b.Instrs {
			// An instruction should always be a Node too.
			if n := instr.(ssa.Node); f(s, n) {
				sources = append(sources, n)
			}
		}
	}
	fMap[current] = sources
}

// For testing purposes only: an analyzer that identifies where sources are
// Wrap the source identification into an analysis pass for testing purposes
var taintSourcesAnalyzer = &analysis.Analyzer{
	Name:     "taint_sources",
	Doc:      "Reports taint sources in Go code for testing.",
	Run:      runSourcesAnalysis,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// newSourceMap builds a SourceMap by inspecting the ssa for each function inside each package.
func newSourceMap(s *dataflow.AnalyzerState) PackageToNodes {
	return NewPackagesMap(s, taint.IsSomeSourceNode)
}

// newSinkMap builds a SinkMap by inspecting the ssa for each function inside each package.
func newSinkMap(s *dataflow.AnalyzerState) PackageToNodes {
	return NewPackagesMap(s,
		func(s *dataflow.AnalyzerState, node ssa.Node) bool {
			return taint.IsMatchingCodeIDWithCallee(s.Config.IsSomeSink, nil, node)
		})
}

func runSourcesAnalysis(pass *analysis.Pass) (interface{}, error) {
	testConfig, err := config.LoadGlobal()
	if err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}
	ssaInfo := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	s, err := dataflow.NewAnalyzerState(ssaInfo.Pkg.Prog, nil, config.NewLogGroup(testConfig), testConfig,
		[]func(state *dataflow.AnalyzerState){})
	if err != nil {
		return nil, err
	}
	sourceMap := newSourceMap(s)
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
	// TaintFlows
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(wd, "testdata")
	// Load config
	configFile := filepath.Join(testdata, "src/sources/config.yaml")
	config.SetGlobalConfig(configFile)
	analysistest.Run(t, testdata, taintSourcesAnalyzer, "sources")
}

// For testing purposes only: an analyzer that identifies where sources are
// Wrap the source identification into an analysis pass for testing purposes
var taintSinksAnalyzer = &analysis.Analyzer{
	Name:     "taint_sinks",
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
	s, err := dataflow.NewAnalyzerState(ssaInfo.Pkg.Prog, nil, config.NewLogGroup(testConfig), testConfig,
		[]func(state *dataflow.AnalyzerState){})
	if err != nil {
		return nil, err
	}
	sourceMap := newSinkMap(s)
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
	// TaintFlows
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(wd, "testdata")
	// Load config
	configFile := filepath.Join(testdata, "src/sinks/config.yaml")
	config.SetGlobalConfig(configFile)
	analysistest.Run(t, testdata, taintSinksAnalyzer, "sinks")
}
