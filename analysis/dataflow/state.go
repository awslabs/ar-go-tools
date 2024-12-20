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

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

// State holds information that might need to be used during program analysis, and represents the state of
// the analyzer. Different steps of the analysis will populate the fields of this structure.
type State struct {
	ptr.State

	// A map from types to functions implementing that type
	//
	// If t is the signature of an interface's method, then map[t.string()] will return all the implementations of
	// that method.
	//
	// If t is the signature of a function, then map[t.string()] will return all the functions matching that type.
	ImplementationsByType map[string]map[*ssa.Function]bool
	MethodKeys            map[string]string

	// DataFlowContracts are dataflow graphs for interfaces.
	DataFlowContracts map[string]*SummaryGraph

	// The global analysis
	Globals map[*ssa.Global]*GlobalNode

	// The dataflow analysis results
	FlowGraph *InterProceduralFlowGraph

	// The escape analysis state
	EscapeAnalysisState EscapeAnalysisState

	// BoundingInfo is a map from pointer labels to the closures that bind them. The bounding analysis produces such
	// a map
	BoundingInfo BoundingMap
}

// NewState generates a State from a PointerState
// This consists in:
//   - computing a map from interface types to the implementations of their methods
//   - scanning the usage of globals in the program
//   - linking aliases of bound variables to the closure that binds them
//
// The State returned *does not* have dataflow information computed yet.
func NewState(ps *ptr.State) result.Result[State] {
	state, err := initializedState(*ps, []func(*State){
		func(s *State) { s.PopulateImplementations() },
		func(s *State) { s.PopulateGlobalsVerbose() },
		func(s *State) {
			err := s.PopulateBoundingInformation(true)
			if err != nil {
				ps.Logger.Errorf("error while running bounding analysis: %v", err)
			}
		},
	})
	if err != nil {
		return result.Err[State](fmt.Errorf("error while running parallel steps: %v", err))
	}
	return result.Ok(state)
}

// initializedState returns a properly initialized analyzer state by running essential steps in parallel.
func initializedState(ps ptr.State, steps []func(*State)) (*State, error) {
	var allContracts []Contract
	// New state with initial cha callgraph
	state := &State{
		State:                 ps,
		ImplementationsByType: map[string]map[*ssa.Function]bool{},
		DataFlowContracts:     map[string]*SummaryGraph{},
		MethodKeys:            map[string]string{},
		Globals:               map[*ssa.Global]*GlobalNode{},
		FlowGraph: &InterProceduralFlowGraph{
			Summaries:     map[*ssa.Function]*SummaryGraph{},
			ForwardEdges:  map[GraphNode]map[GraphNode]bool{},
			BackwardEdges: map[GraphNode]map[GraphNode]bool{},
			Globals:       map[*GlobalNode]map[*AccessGlobalNode]bool{},
			AnalyzerState: nil,
		},
	}
	// Link summaries to parent analyzer state
	state.FlowGraph.AnalyzerState = state

	// Load the dataflow contracts from the specified json files, if any
	if len(ps.Config.DataflowProblems.UserSpecs) > 0 {
		for _, specFile := range ps.Config.DataflowProblems.UserSpecs {
			contractsBatch, err := LoadDefinitions(ps.Config.RelPath(specFile))
			if err != nil {
				return nil, err
			}
			ps.Logger.Debugf("Loaded %d dataflow contracts from %s\n", len(contractsBatch), specFile)
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
	if errs := state.Report.CheckError(); len(errs) > 0 {
		// TODO: use errors.Join when min version of go is 1.20
		// currently only first error is reported
		return nil, fmt.Errorf("failed to build analyzer state: %w", errs[0])
	}

	state.linkContracts(allContracts)

	return state, nil
}

// Size returns the number of method implementations collected
func (s *State) Size() int {
	return len(s.ImplementationsByType)
}

// PrintImplementations prints out all the implementations that the
// State has collected, organized by type. For each type, it prints
// the type name followed by each implemented function name.
//
// The implementations are printed to the given io.Writer. Typically, this
// would be os.Stdout to print to the standard output.
//
// This can be useful for debugging the implementations collected during
// analysis or for displaying final results.
func (s *State) PrintImplementations(w io.Writer) {
	for typString, implems := range s.ImplementationsByType {
		fmt.Fprintf(w, "KEY: %s\n", typString)
		for function := range implems {
			fmt.Fprintf(w, "\tFUNCTION: %s\n", function.String())
		}
	}
}

// PopulateTypesToImplementationMap populates the implementationsByType maps from type strings to implementations
func (s *State) PopulateTypesToImplementationMap() {
	if err := ComputeMethodImplementations(s.Program, s.ImplementationsByType, s.DataFlowContracts, s.MethodKeys); err != nil {
		s.Report.AddError("implementationsmap", err)
	}
}

// PopulateImplementations is a verbose wrapper around PopulateTypesToImplementationsMap.
func (s *State) PopulateImplementations() {
	// Load information for analysis and cache it.
	s.Logger.Infof("Computing information about types and functions for analysis...")
	start := time.Now()
	s.PopulateTypesToImplementationMap()
	s.Logger.Infof("Pointer analysis state computed, added %d items (%.2f s)\n",
		s.Size(), time.Since(start).Seconds())
}

// PopulateGlobals adds global nodes for every global defined in the program's packages
func (s *State) PopulateGlobals() {
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
func (s *State) PopulateGlobalsVerbose() {
	start := time.Now()
	s.Logger.Infof("Gathering global variable declaration in the program...")
	s.PopulateGlobals()
	s.Logger.Infof("Global gathering terminated, added %d items (%.2f s)",
		len(s.Globals), time.Since(start).Seconds())
}

// PopulateBoundingInformation runs the bounding analysis
func (s *State) PopulateBoundingInformation(verbose bool) error {
	start := time.Now()
	s.Logger.Debugf("Gathering information about pointer binding in closures")
	boundingInfo, err := RunBoundingAnalysis(s)
	if err != nil {
		if verbose {
			s.Logger.Errorf("Error running pointer binding analysis:")
			s.Logger.Errorf("  %s", err)
		}
		s.Report.AddError("bounding analysis", err)
		return err
	}
	s.BoundingInfo = boundingInfo
	s.Logger.Debugf("Pointer binding analysis terminated, added %d items (%.2f s)",
		len(s.BoundingInfo), time.Since(start).Seconds())
	return nil
}

// Functions to retrieve results from the information stored in the analyzer state

// IsReachableFunction returns true if f is reachable according to the pointer analysis, or if the pointer analysis
// and ReachableFunctions has never been called.
func (s *State) IsReachableFunction(f *ssa.Function) bool {
	if s != nil && s.ReachableFunctions() != nil {
		return s.ReachableFunctions()[f]
	}
	// If no reachability information has been computed, assume every function is reachable
	s.Logger.Debugf("No reachability information has been computed")
	return true
}

/* Functions for callee resolution */

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
func (s *State) ResolveCallee(instr ssa.CallInstruction, useContracts bool) (map[*ssa.Function]lang.CalleeInfo, error) {
	// First, check if there is a static callee
	callee := instr.Common().StaticCallee()
	if callee != nil {
		return map[*ssa.Function]lang.CalleeInfo{callee: {Callee: callee, Type: lang.Static}}, nil
	}

	mKey := lang.InstrMethodKey(instr)

	if useContracts {
		// If it is a method, try first to find an interface contract, and return the implementation that is used
		// in the summary of the contract.
		// Instead of considering all implementations, this means we have only one summarized implementation for
		// an interface method invocation
		if summary, ok := s.DataFlowContracts[mKey.ValueOr("")]; ok && summary != nil {
			info := lang.CalleeInfo{Callee: summary.Parent, Type: lang.InterfaceContract}
			return map[*ssa.Function]lang.CalleeInfo{summary.Parent: info}, nil
		}
	}

	callees := map[*ssa.Function]lang.CalleeInfo{}

	// Try using the callgraph from the pointer analysis
	if s.PointerAnalysis != nil {
		node, ok := s.PointerAnalysis.CallGraph.Nodes[instr.Parent()]
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
	}

	// Last option is to use the map from type string to implementation
	if s.ImplementationsByType == nil || len(s.ImplementationsByType) == 0 {
		return nil, fmt.Errorf("cannot resolve callee without information about possible implementations")
	}

	if implementations, ok := s.ImplementationsByType[mKey.ValueOr("")]; ok {
		for implementation := range implementations {
			callees[implementation] = lang.CalleeInfo{Callee: implementation, Type: lang.InterfaceMethod}
		}
	}
	return callees, nil
}

/*  Functions specific to dataflow contracts stored in the analyzer state */

// linkContracts implements the step in the analyzer state building function that links every dataflow contract with
// a specific SSA function. This step should only link function contracts with the SSA function, but it builds the
// summaries for all contracts in allContracts.
func (s *State) linkContracts(allContracts []Contract) {
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
func (s *State) HasExternalContractSummary(f *ssa.Function) bool {
	// Indirection: look for interface contract
	if interfaceMethodKey, ok := s.MethodKeys[f.String()]; ok {
		return s.DataFlowContracts[interfaceMethodKey] != nil
	}
	// Look for direct contract
	if _, ok := s.DataFlowContracts[f.String()]; ok {
		return true
	}
	return false
}

// LoadExternalContractSummary looks for contracts loaded in the DataFlowContracts of the state.
func (s *State) LoadExternalContractSummary(node *CallNode) *SummaryGraph {
	if node == nil || node.callee.Callee == nil {
		return nil
	}

	// Look first for interface contracts, they have precedence over function contracts
	if isKey, methodKey := InterfaceMethodKey(node.CallSite()); isKey && node.callee.Type == lang.InterfaceContract {
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
