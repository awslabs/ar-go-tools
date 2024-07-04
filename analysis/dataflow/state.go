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

package dataflow

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/annotations"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// AnalyzerState holds information that might need to be used during program analysis, and represents the state of
// the analyzer. Different steps of the analysis will populate the fields of this structure.
type AnalyzerState struct {
	// Annotations contains all the annotations of the program
	Annotations annotations.ProgramAnnotations

	// The logger used during the analysis (can be used to control output.
	Logger *config.LogGroup

	// The configuration file for the analysis
	Config *config.Config

	// Packages store the packages initially loaded. Can be used to seek syntactic information
	Packages []*packages.Package

	// The program to be analyzed. It should be a complete buildable program (e.g. loaded by LoadProgram).
	Program *ssa.Program

	// A map from types to functions implementing that type
	//
	// If t is the signature of an interface's method, then map[t.string()] will return all the implementations of
	// that method.
	//
	// If t is the signature of a function, then map[t.string()] will return all the functions matching that type.
	ImplementationsByType map[string]map[*ssa.Function]bool
	keys                  map[string]string

	// DataFlowContracts are dataflow graphs for interfaces.
	DataFlowContracts map[string]*SummaryGraph

	// The result of a pointer analysis.
	PointerAnalysis *pointer.Result

	// The global analysis
	Globals map[*ssa.Global]*GlobalNode

	// The dataflow analysis results
	FlowGraph *InterProceduralFlowGraph

	// The escape analysis state
	EscapeAnalysisState EscapeAnalysisState

	// BoundingInfo is a map from pointer labels to the closures that bind them. The bounding analysis produces such
	// a map
	BoundingInfo BoundingMap

	reachableFunctions map[*ssa.Function]bool

	// a callgraph computed using the cha analysis. Useful to boostrap the reachable functions
	chaCallgraph      *callgraph.Graph
	isReachabilityCha bool

	// Stored errors
	errors     map[string][]error
	errorMutex sync.Mutex
}

// NewInitializedAnalyzerState runs NewAnalyzerState, and any additional steps that are commonly used in analyses.
// This consists in:
//   - building the ssa program
//   - running pointer analysis
//   - computing a map from interface types to the implementations of their methods
//   - scanning the usage of globals in the program
//   - linking aliases of bound variables to the closure that binds them
func NewInitializedAnalyzerState(program *ssa.Program, pkgs []*packages.Package,
	logger *config.LogGroup, config *config.Config) (*AnalyzerState, error) {
	program.Build()
	state, err := NewAnalyzerState(program, pkgs, logger, config, []func(*AnalyzerState){
		func(s *AnalyzerState) { s.PopulateImplementations() },
		func(s *AnalyzerState) { s.PopulatePointersVerbose(summaries.IsUserDefinedFunction) },
		func(s *AnalyzerState) { s.PopulateGlobalsVerbose() },
	})
	if err != nil {
		return state, fmt.Errorf("error while running parallel steps: %v", err)
	}
	err = state.PopulateBoundingInformation(true)
	if err != nil {
		return state, fmt.Errorf("error while running bounding analysis: %v", err)
	}
	return state, err
}

// NewAnalyzerState returns a properly initialized analyzer state by running essential steps in parallel.
func NewAnalyzerState(p *ssa.Program, pkgs []*packages.Package, l *config.LogGroup, c *config.Config,
	steps []func(*AnalyzerState)) (*AnalyzerState, error) {
	var allContracts []Contract

	// Load annotations
	pa, err := annotations.LoadAnnotations(l, p.AllPackages())
	if pkgs != nil {
		pa.CompleteFromSyntax(pkgs)
	}

	if err != nil {
		return nil, err
	}
	l.Infof("Loaded %d annotations from program\n", pa.Count())

	// New state with initial cha callgraph
	state := &AnalyzerState{
		Annotations:           pa,
		Logger:                l,
		Config:                c,
		Packages:              pkgs,
		Program:               p,
		ImplementationsByType: map[string]map[*ssa.Function]bool{},
		DataFlowContracts:     map[string]*SummaryGraph{},
		keys:                  map[string]string{},
		PointerAnalysis:       nil,
		Globals:               map[*ssa.Global]*GlobalNode{},
		FlowGraph: &InterProceduralFlowGraph{
			Summaries:     map[*ssa.Function]*SummaryGraph{},
			ForwardEdges:  map[GraphNode]map[GraphNode]bool{},
			BackwardEdges: map[GraphNode]map[GraphNode]bool{},
			Globals:       map[*GlobalNode]map[*AccessGlobalNode]bool{},
			AnalyzerState: nil,
		},
		chaCallgraph:      cha.CallGraph(p),
		isReachabilityCha: false,
		errors:            map[string][]error{},
	}
	// Link summaries to parent analyzer state
	state.FlowGraph.AnalyzerState = state

	// Load the dataflow contracts from the specified json files, if any
	if len(c.DataflowSpecs) > 0 {
		for _, specFile := range c.DataflowSpecs {
			contractsBatch, err := LoadDefinitions(c.RelPath(specFile))
			if err != nil {
				return nil, err
			}
			l.Debugf("Loaded %d dataflow contracts from %s\n", len(contractsBatch), specFile)
			// Initialize all the entries of DataFlowContracts
			for _, contract := range contractsBatch {
				for method := range contract.Methods {
					// contract are initially nil, the calls to ResolveCallee will set them to some non-nil value
					// when necessary
					state.DataFlowContracts[contract.Key(method)] = nil
				}
			}
			allContracts = append(allContracts, contractsBatch...)
		}
	}

	// if no steps are provided, there is no additional information to compute here.
	// link contracts (using the reachable functions from the cha analysis)
	if steps == nil {
		state.linkContracts(allContracts)
		return state, nil
	}

	wg := &sync.WaitGroup{}
	for _, step := range steps {
		step := step
		wg.Add(1)
		go func() {
			defer wg.Done()
			step(state)
		}()
	}
	wg.Wait()
	if errs := state.CheckError(); len(errs) > 0 {
		// TODO: use errors.Join when min version of go is 1.20
		// currently only first error is reported
		return nil, fmt.Errorf("failed to build analyzer state: %w", errs[0])
	}

	state.linkContracts(allContracts)

	return state, nil
}

// NewDefaultAnalyzer returns a new analyzer with a default config and a default log group.
// This is useful if you only need the basic functionality, for example callgraph construction
// and pointer analysis.
func NewDefaultAnalyzer(p *ssa.Program, pkgs []*packages.Package) (*AnalyzerState, error) {
	defaultConfig := config.NewDefault()
	defaultLogGroup := config.NewLogGroup(defaultConfig)
	return NewAnalyzerState(p, pkgs, defaultLogGroup, defaultConfig, nil)
}

// CopyTo copies pointers in receiver into argument (shallow copy of everything except mutex).
// Do not use two copies in separate routines.
func (s *AnalyzerState) CopyTo(b *AnalyzerState) {
	b.BoundingInfo = s.BoundingInfo
	b.Config = s.Config
	b.EscapeAnalysisState = s.EscapeAnalysisState
	b.FlowGraph = s.FlowGraph
	b.Globals = s.Globals
	b.ImplementationsByType = s.ImplementationsByType
	b.Logger = s.Logger
	b.PointerAnalysis = s.PointerAnalysis
	b.errors = s.errors
	b.Program = s.Program
	b.keys = s.keys
	b.reachableFunctions = s.reachableFunctions
	// copy everything except mutex
}

// Size returns the number of method implementations collected
func (s *AnalyzerState) Size() int {
	return len(s.ImplementationsByType)
}

// PrintImplementations prints out all the implementations that the
// AnalyzerState has collected, organized by type. For each type, it prints
// the type name followed by each implemented function name.
//
// The implementations are printed to the given io.Writer. Typically, this
// would be os.Stdout to print to the standard output.
//
// This can be useful for debugging the implementations collected during
// analysis or for displaying final results.
func (s *AnalyzerState) PrintImplementations(w io.Writer) {
	for typString, implems := range s.ImplementationsByType {
		fmt.Fprintf(w, "KEY: %s\n", typString)
		for function := range implems {
			fmt.Fprintf(w, "\tFUNCTION: %s\n", function.String())
		}
	}
}

// AddError adds an error with key and error e to the state.
func (s *AnalyzerState) AddError(key string, e error) {
	s.errorMutex.Lock()
	defer s.errorMutex.Unlock()
	if e != nil {
		s.errors[key] = append(s.errors[key], e)
	}
}

// CheckError checks whether there is an error in the state, and if there is, returns the first it encounters and
// deletes it. The slice returned contains all the errors associated with one single error key (as used in
// [*AnalyzerState.AddError])
func (s *AnalyzerState) CheckError() []error {
	s.errorMutex.Lock()
	defer s.errorMutex.Unlock()
	for e, errs := range s.errors {
		delete(s.errors, e)
		return errs
	}
	return nil
}

// HasErrors returns true if the state has an error. Unlike [*AnalyzerState.CheckError], this is non-destructive.
func (s *AnalyzerState) HasErrors() bool {
	s.errorMutex.Lock()
	defer s.errorMutex.Unlock()
	for _, errs := range s.errors {
		if len(errs) > 0 {
			return true
		}
	}
	return false
}

// PopulateTypesToImplementationMap populates the implementationsByType maps from type strings to implementations
func (s *AnalyzerState) PopulateTypesToImplementationMap() {
	if err := ComputeMethodImplementations(s.Program, s.ImplementationsByType, s.DataFlowContracts, s.keys); err != nil {
		s.AddError("implementationsmap", err)
	}
}

// PopulateImplementations is a verbose wrapper around PopulateTypesToImplementationsMap.
func (s *AnalyzerState) PopulateImplementations() {
	// Load information for analysis and cache it.
	s.Logger.Infof("Computing information about types and functions for analysis...")
	start := time.Now()
	s.PopulateTypesToImplementationMap()
	s.Logger.Infof("Pointer analysis state computed, added %d items (%.2f s)\n",
		s.Size(), time.Since(start).Seconds())
}

// PopulatePointerAnalysisResult populates the PointerAnalysis field of the analyzer state by running the pointer analysis
// with queries on every function in the package such that functionFilter is true.
//
// The analyzer state contains the result of the pointer analysis, or an error that can be inspected by CheckError
func (s *AnalyzerState) PopulatePointerAnalysisResult(functionFilter func(*ssa.Function) bool) {
	ptrResult, err := DoPointerAnalysis(s.Config, s.Program, functionFilter, s.ReachableFunctions())
	if err != nil {
		s.AddError("pointeranalysis", err)
	}
	s.PointerAnalysis = ptrResult
}

// PopulatePointersVerbose is a verbose wrapper around PopulatePointerAnalysisResult.
func (s *AnalyzerState) PopulatePointersVerbose(functionFilter func(*ssa.Function) bool) {
	start := time.Now()
	s.Logger.Infof("Gathering values and starting pointer analysis...")
	s.PopulatePointerAnalysisResult(functionFilter)
	s.Logger.Infof("Pointer analysis terminated (%.2f s)", time.Since(start).Seconds())
}

// PopulateGlobals adds global nodes for every global defined in the program's packages
func (s *AnalyzerState) PopulateGlobals() {
	for _, pkg := range s.Program.AllPackages() {
		for _, member := range pkg.Members {
			glob, ok := member.(*ssa.Global)
			if ok {
				s.Globals[glob] = newGlobalNode(glob)
			}
		}
	}
}

// PopulateGlobalsVerbose is a verbose wrapper around PopulateGlobals
func (s *AnalyzerState) PopulateGlobalsVerbose() {
	start := time.Now()
	s.Logger.Infof("Gathering global variable declaration in the program...")
	s.PopulateGlobals()
	s.Logger.Infof("Global gathering terminated, added %d items (%.2f s)",
		len(s.Globals), time.Since(start).Seconds())
}

// PopulateBoundingInformation runs the bounding analysis
func (s *AnalyzerState) PopulateBoundingInformation(verbose bool) error {
	start := time.Now()
	s.Logger.Debugf("Gathering information about pointer binding in closures")
	boundingInfo, err := RunBoundingAnalysis(s)
	if err != nil {
		if verbose {
			s.Logger.Errorf("Error running pointer binding analysis:")
			s.Logger.Errorf("  %s", err)
		}
		s.AddError("bounding analysis", err)
		return err
	}
	s.BoundingInfo = boundingInfo
	s.Logger.Debugf("Pointer binding analysis terminated, added %d items (%.2f s)",
		len(s.BoundingInfo), time.Since(start).Seconds())
	return nil
}

// Functions to retrieve results from the information stored in the analyzer state

// ReachableFunctions returns the set of reachable functions from main and init according to:
// - the pointer analysis if it has been computed, otherwise
// - the cha analysis if it has been computed, oterhwise
// - an empty map.
// To compute reachable functions without main or init, use the CallGraphReachable function with
// the appropriate callgraph information.
func (s *AnalyzerState) ReachableFunctions() map[*ssa.Function]bool {
	// Create reachability information using best available callgraph
	if s.reachableFunctions == nil {
		s.reachableFunctions = make(map[*ssa.Function]bool)
		if s.PointerAnalysis != nil {
			s.reachableFunctions = CallGraphReachable(s.PointerAnalysis.CallGraph, false, false)
			s.isReachabilityCha = false
			return s.reachableFunctions
		}
		if s.chaCallgraph != nil {
			s.reachableFunctions = CallGraphReachable(s.chaCallgraph, false, false)
			s.isReachabilityCha = true
			return s.reachableFunctions
		}
	}
	// Attempt update of reachability information
	if s.isReachabilityCha && s.PointerAnalysis != nil {
		s.reachableFunctions = CallGraphReachable(s.PointerAnalysis.CallGraph, false, false)
	}
	return s.reachableFunctions
}

// IsReachableFunction returns true if f is reachable according to the pointer analysis, or if the pointer analysis
// and ReachableFunctions has never been called.
func (s *AnalyzerState) IsReachableFunction(f *ssa.Function) bool {
	if s != nil && s.reachableFunctions != nil {
		return s.reachableFunctions[f]
	}
	// If no reachability information has been computed, assume every function is reachable
	s.Logger.Debugf("No reachability information has been computed")
	return true
}

/* Functions for callee resolution */

// A CalleeType gives information about how the callee was resolved
type CalleeType int

const (
	// Static indicates the callee is a statically defined function
	Static CalleeType = 1 << iota
	// CallGraph indicates the callee is a function obtained from the call graph
	CallGraph
	// InterfaceContract indicates the callee is obtained from an interface contract (one particular instance
	// of an interface method to stand for all methods)
	InterfaceContract
	// InterfaceMethod indicates the calle is an interface method
	InterfaceMethod
)

// Code returns a short string representation of the type of callee
func (t CalleeType) Code() string {
	switch t {
	case Static:
		return "SA"
	case CallGraph:
		return "CG"
	case InterfaceContract:
		return "IC"
	case InterfaceMethod:
		return "IM"
	default:
		return ""
	}
}

// CalleeInfo decorates a function with some CalleeType that records how the dataflow information of the function
// can be resolved or how the callee's identity was determined
type CalleeInfo struct {
	Callee *ssa.Function
	Type   CalleeType
}

// ResolveCallee resolves the callee(s) at the call instruction instr.
//
// If the callee is statically resolvable, then it returns a single callee.
//
// If the call instruction appears in the callgraph, it returns all the callees at that callsite according to the
// pointer analysis callgraph (requires it to be computed).
//
// If the call instruction does not appear in the callgraph, then it returns all the functions that correspond to the
// type of the call variable at the location.
//
// Returns a non-nil error if it requires some information in the analyzer state that has not been computed.
func (s *AnalyzerState) ResolveCallee(instr ssa.CallInstruction, useContracts bool) (map[*ssa.Function]CalleeInfo, error) {
	// First, check if there is a static callee
	callee := instr.Common().StaticCallee()
	if callee != nil {
		return map[*ssa.Function]CalleeInfo{callee: {Callee: callee, Type: Static}}, nil
	}

	mKey := lang.InstrMethodKey(instr)

	if useContracts {
		// If it is a method, try first to find an interface contract, and return the implementation that is used
		// in the summary of the contract.
		// Instead of considering all implementations, this means we have only one summarized implementation for
		// an interface method invocation
		if summary, ok := s.DataFlowContracts[mKey.ValueOr("")]; ok && summary != nil {
			info := CalleeInfo{Callee: summary.Parent, Type: InterfaceContract}
			return map[*ssa.Function]CalleeInfo{summary.Parent: info}, nil
		}
	}

	callees := map[*ssa.Function]CalleeInfo{}

	// Try using the callgraph from the pointer analysis
	if s.PointerAnalysis != nil {
		node, ok := s.PointerAnalysis.CallGraph.Nodes[instr.Parent()]
		if ok {
			for _, callEdge := range node.Out {
				if callEdge.Site == instr {
					f := callEdge.Callee.Func
					callees[f] = CalleeInfo{Callee: f, Type: CallGraph}
				}
			}
		}
		// If we have found the callees using the callgraph, return
		if len(callees) > 0 {
			return callees, nil
		}
	}

	// Last option is to use the map from type string to implementation
	if s.ImplementationsByType == nil || len(s.ImplementationsByType) == 0 {
		return nil, fmt.Errorf("cannot resolve callee without information about possible implementations")
	}

	if implementations, ok := s.ImplementationsByType[mKey.ValueOr("")]; ok {
		for implementation := range implementations {
			callees[implementation] = CalleeInfo{Callee: implementation, Type: InterfaceMethod}
		}
	}
	return callees, nil
}

/*  Functions specific to dataflow contracts stored in the analyzer state */

// linkContracts implements the step in the analyzer state building function that links every dataflow contract with
// a specific SSA function. This step should only link function contracts with the SSA function, but it build the
// summaries for all contracts in allContracts.
func (s *AnalyzerState) linkContracts(allContracts []Contract) {
	// This links the function contracts to their implementation by storing an empty summary graph in the
	// DataFlowContracts map of the analyzer state.
	for f := range s.ReachableFunctions() {
		if _, hasContract := s.DataFlowContracts[f.String()]; hasContract {
			s.DataFlowContracts[f.String()] = NewSummaryGraph(nil, f, GetUniqueFunctionID(), nil, nil)
		}
	}

	// Every summary for the contract in allContracts must be built
	for _, contract := range allContracts {
		for method, methodSummary := range contract.Methods {
			s.DataFlowContracts[contract.Key(method)].
				PopulateGraphFromSummary(methodSummary, contract.InterfaceID != "")
		}
	}
}

// HasExternalContractSummary returns true if the function f has a summary has been loaded in the DataFlowContracts
// of the analyzer state.
func (s *AnalyzerState) HasExternalContractSummary(f *ssa.Function) bool {
	// Indirection: look for interface contract
	if interfaceMethodKey, ok := s.keys[f.String()]; ok {
		return s.DataFlowContracts[interfaceMethodKey] != nil
	}
	// Look for direct contract
	if _, ok := s.DataFlowContracts[f.String()]; ok {
		return true
	}
	return false
}

// LoadExternalContractSummary looks for contracts loaded in the DataFlowContracts of the state.
func (s *AnalyzerState) LoadExternalContractSummary(node *CallNode) *SummaryGraph {
	if node == nil || node.callee.Callee == nil {
		return nil
	}

	// Look first for interface contracts, they have precedence over function contracts
	if isKey, methodKey := InterfaceMethodKey(node.CallSite()); isKey && node.callee.Type == InterfaceContract {
		if summary, ok := s.DataFlowContracts[methodKey]; ok {
			return summary
		}
	}

	// Look for a function contract
	if summary, ok := s.DataFlowContracts[node.callee.Callee.String()]; ok {
		return summary
	}

	return nil
}
