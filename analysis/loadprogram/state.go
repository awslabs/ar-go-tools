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

package loadprogram

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sync/atomic"

	"github.com/awslabs/ar-go-tools/analysis/annotations"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// A State is the base state for the analyses in Argot. Analyses that do not require whole-program analysis
// should be built with the go tools analysis framework (https://pkg.go.dev/golang.org/x/tools/go/analysis)
type State struct {
	config.State

	// Annotations contains all the annotations of the program
	Annotations annotations.ProgramAnnotations

	// Packages store the packages initially loaded. Can be used to seek syntactic information
	Packages []*packages.Package

	// The program to be analyzed. It should be a complete buildable program (e.g. loaded by LoadProgram).
	Program *ssa.Program

	// Report contains the accumulated report information
	Report *config.ReportInfo

	// a callgraph computed using the cha analysis. Useful to boostrap the reachable functions
	chaCallgraph       *callgraph.Graph
	reachableFunctions map[*ssa.Function]bool

	numAlarms atomic.Int32
}

// NewState construct a whole program state from the provided SSA program and packages, and the config
// with its logger. The packages are visited to extract all the annotations in the program.
func NewState(c *config.State) result.Result[State] {
	if c == nil || c.Config == nil {
		return result.Err[State](fmt.Errorf("cannot create state without config"))
	}

	program, pkgs, err := do(c.Patterns, c.Options)
	if err != nil {
		return result.Err[State](fmt.Errorf("failed to build program: %s", err))
	}
	// Load annotations by scanning all packages' syntax
	pa, err := annotations.LoadAnnotations(c.Logger, program.AllPackages())
	if err != nil {
		return result.Err[State](fmt.Errorf("failed to load annotations from SSA"))
	}

	dirs := c.Patterns
	// If the project root is set, parse all Go files inside the root directory (recursively)
	if root := c.Config.Root(); root != "" {
		dirs = []string{root}
	}

	files, err := allAstFiles(dirs, program.Fset, pkgs)
	if err != nil {
		return result.Err[State](fmt.Errorf("failed to parse AST files: %v", err))
	}

	pa.CompleteFromSyntax(c.Logger, program.Fset, files)
	c.Logger.Infof("Loaded %d annotations from program\n", pa.Count())

	report := config.NewReport()

	return result.Ok(&State{
		State:        *c,
		Annotations:  pa,
		Packages:     pkgs,
		Program:      program,
		Report:       report,
		chaCallgraph: nil,
	})
}

func (wps *State) ensureCallgraph() error {
	if wps.chaCallgraph == nil {
		wps.chaCallgraph = cha.CallGraph(wps.Program)
	}
	if wps.chaCallgraph == nil {
		return fmt.Errorf("error computing callgraph")
	}
	return nil
}

// Functions to retrieve results from the information stored in the analyzer state

// ReachableFunctions returns the set of reachable functions from main and init according to the CHA analysis.
func (wps *State) ReachableFunctions() (map[*ssa.Function]bool, error) {
	err := wps.ensureCallgraph()
	if err != nil {
		return nil, err
	}
	if wps.reachableFunctions == nil {
		wps.reachableFunctions = lang.CallGraphReachable(wps.chaCallgraph, false, false)
		return wps.reachableFunctions, nil
	}
	return wps.reachableFunctions, nil
}

// ResolveCallee resolves the callee(s) at the call instruction instr.
// It resolves callees by first looking into static callees, and then the CHA callgraph if no static callee is found.
func (wps *State) ResolveCallee(instr ssa.CallInstruction) (map[*ssa.Function]lang.CalleeInfo, error) {
	// First, check if there is a static callee
	callee := instr.Common().StaticCallee()
	if callee != nil {
		return map[*ssa.Function]lang.CalleeInfo{callee: {Callee: callee, Type: lang.Static}}, nil
	}

	callees := map[*ssa.Function]lang.CalleeInfo{}
	// Try using the callgraph
	err := wps.ensureCallgraph()
	if err != nil {
		return nil, err
	}
	node, ok := wps.chaCallgraph.Nodes[instr.Parent()]
	if ok {
		for _, callEdge := range node.Out {
			if callEdge.Site == instr {
				f := callEdge.Callee.Func
				callees[f] = lang.CalleeInfo{Callee: f, Type: lang.CallGraph}
			}
		}
	}
	// If we have found the callees using the callgraph, return
	if len(callees) > 0 {
		return callees, nil
	}

	return nil, fmt.Errorf("could not find callees using whole-program-state")
}

// ResetAlarms resets the number of alarms to 0
func (wps *State) ResetAlarms() {
	wps.numAlarms.Store(0)
}

// IncrementAndTestAlarms increments the alarm counter in the state, and returns false if the count is larger
// than the MaxAlarms setting in the config.
func (wps *State) IncrementAndTestAlarms() bool {
	wps.numAlarms.Add(1)
	return wps.TestAlarmCount()
}

// TestAlarmCount tests whether the alarm count is smaller than the maximum number of alarms allowed by the configuration.
func (wps *State) TestAlarmCount() bool {
	return wps.Config.MaxAlarms <= 0 || wps.numAlarms.Load() < int32(wps.Config.MaxAlarms)
}

func allAstFiles(dirs []string, fset *token.FileSet, pkgs []*packages.Package) ([]*ast.File, error) {
	var files []*ast.File

	// HACK Ideally, this loop shouldn't be necessary but sometimes
	// analysisutil.VisitPackages will miss some AST files.
	// Hopefully there's a better way to get all the AST files in the program
	// without needing to parse it twice.
	for _, dir := range dirs {
		if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				// Parse all files in the directory, making sure to include comments
				parsedDir, err := parser.ParseDir(fset, path, nil, parser.ParseComments)
				if err != nil {
					return fmt.Errorf("failed to parse dir %s: %v", path, err)
				}

				for _, pkg := range parsedDir {
					for _, file := range pkg.Files {
						files = append(files, file)
					}
				}
			}

			return nil
		}); err != nil {
			return nil, fmt.Errorf("failed to parse AST files: %v", err)
		}
	}

	if pkgs != nil {
		for _, pkg := range pkgs {
			analysisutil.VisitPackages(pkg, func(p *packages.Package) bool {
				// Don't scan stdlib for annotations!
				if summaries.IsStdPackageName(p.Name) {
					return false
				}

				// TODO: Remove if there is no need for scanning dependencies
				files = append(files, p.Syntax...)

				return true
			})
		}
	}

	return files, nil
}
