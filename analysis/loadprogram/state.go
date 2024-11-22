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
	"sync"
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
// should be built with the go tools analysis framework.
type State struct {
	*config.State
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

	// Stored errors
	numAlarms  atomic.Int32
	errors     map[string][]error
	errorMutex sync.Mutex
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

	if pkgs != nil {
		for _, pkg := range pkgs {
			analysisutil.VisitPackages(pkg, func(p *packages.Package) bool {
				// Don't scan stdlib for annotations!
				if summaries.IsStdPackageName(p.Name) {
					return false
				}
				// TODO: find a way to not scan dependencies if there is demand. Currently, it is unlikely that some
				// dependencies will contain argot annotations.
				c.Logger.Debugf("Scan %s for annotations.\n", p.PkgPath)
				pa.CompleteFromSyntax(c.Logger, p)
				return true
			})
		}
	}
	if err != nil {
		return result.Err[State](err)
	}
	c.Logger.Infof("Loaded %d annotations from program\n", pa.Count())

	report := config.NewReport()

	return result.Ok(&State{
		State:        c,
		Annotations:  pa,
		Packages:     pkgs,
		Program:      program,
		Report:       &report,
		chaCallgraph: nil,
		errors:       map[string][]error{},
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

// AddError adds an error with key and error e to the state.
func (wps *State) AddError(key string, e error) {
	wps.errorMutex.Lock()
	defer wps.errorMutex.Unlock()
	if e != nil {
		wps.errors[key] = append(wps.errors[key], e)
	}
}

// CheckError checks whether there is an error in the state, and if there is, returns the first it encounters and
// deletes it. The slice returned contains all the errors associated with one single error key (as used in
// [*AnalyzerState.AddError])
func (wps *State) CheckError() []error {
	wps.errorMutex.Lock()
	defer wps.errorMutex.Unlock()
	for e, errs := range wps.errors {
		delete(wps.errors, e)
		return errs
	}
	return nil
}

// HasErrors returns true if the state has an error. Unlike [*AnalyzerState.CheckError], this is non-destructive.
func (wps *State) HasErrors() bool {
	wps.errorMutex.Lock()
	defer wps.errorMutex.Unlock()
	for _, errs := range wps.errors {
		if len(errs) > 0 {
			return true
		}
	}
	return false
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
