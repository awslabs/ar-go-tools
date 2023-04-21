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
	"log"
	"sync"
	"time"

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/ssafuncs"
	"github.com/awslabs/argot/analysis/summaries"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// Cache holds information that might need to be used during program analysis
type Cache struct {
	// The logger used during the analysis (can be used to control output.
	Logger *log.Logger

	// Err is a Logger for errors
	Err *log.Logger

	// The configuration file for the analysis
	Config *config.Config

	// The program to be analyzed. It should be a complete buildable program (e.g. loaded by LoadProgram).
	Program *ssa.Program

	// A map from types to functions implementing that type
	//
	// If t is the signature of an interface's method, then map[t.string()] will return all the implementations of
	// that method.
	//
	// If t is the signature of a function, then map[t.string()] will return all the functions matching that type.
	implementationsByType map[string]map[*ssa.Function]bool
	keys                  map[string]string

	// DataFlowContracts are dataflow graphs for interfaces.
	DataFlowContracts map[string]*SummaryGraph

	// The result of a pointer analysis.
	PointerAnalysis *pointer.Result

	// The global analysis
	Globals map[*ssa.Global]*GlobalNode

	// The dataflow analysis results
	FlowGraph *CrossFunctionFlowGraph

	// BoundingInfo is a map from pointer labels to the closures that bind them. The bounding analysis produces such
	// a map
	BoundingInfo BoundingMap

	reachableFunctions map[*ssa.Function]bool

	// Stored errors
	errors     map[string][]error
	errorMutex sync.Mutex
}

// BuildFullCache runs NewCache, building all information that can be built in the cache
func BuildFullCache(logger *log.Logger, config *config.Config, program *ssa.Program) (*Cache, error) {
	program.Build()
	c, err := NewCache(program, logger, config, []func(*Cache){
		func(cache *Cache) { cache.PopulateImplementations() },
		func(cache *Cache) { cache.PopulatePointersVerbose(summaries.IsUserDefinedFunction) },
		func(cache *Cache) { cache.PopulateGlobalsVerbose() },
	})
	if err != nil {
		return c, fmt.Errorf("error while running parallel steps: %v", err)
	}
	err = c.PopulateBoundingInformation(true)
	if err != nil {
		return c, fmt.Errorf("error while running bounding analysis: %v", err)
	}
	return c, err
}

// NewCache returns a properly initialized cache by running steps in parallel.
func NewCache(p *ssa.Program, l *log.Logger, c *config.Config, steps []func(*Cache)) (*Cache, error) {
	var allContracts []Contract

	e := log.New(l.Writer(), "[ERROR] ", l.Flags())

	cache := &Cache{
		Logger:                l,
		Err:                   e,
		Config:                c,
		Program:               p,
		implementationsByType: map[string]map[*ssa.Function]bool{},
		DataFlowContracts:     map[string]*SummaryGraph{},
		keys:                  map[string]string{},
		PointerAnalysis:       nil,
		Globals:               map[*ssa.Global]*GlobalNode{},
		FlowGraph: &CrossFunctionFlowGraph{
			Summaries: map[*ssa.Function]*SummaryGraph{},
			cache:     nil,
		},
		errors: map[string][]error{},
	}
	// Link summaries to parent cache
	cache.FlowGraph.cache = cache

	// Load the dataflow contracts from the specified json files, if any
	if len(c.DataflowSpecs) > 0 {
		for _, specFile := range c.DataflowSpecs {
			contractsBatch, err := LoadDefinitions(c.RelPath(specFile))
			if err != nil {
				return nil, err
			}
			if c.Verbose {
				l.Printf("Loaded %d dataflow contracts from %s\n", len(contractsBatch), specFile)
			}
			// Initialize all the entries of DataFlowContracts
			for _, contract := range contractsBatch {
				for method := range contract.Methods {
					// contract are initially nil, the calls to ResolveCallee will set them to some non-nil value
					// when necessary
					cache.DataFlowContracts[contract.Key(method)] = nil
				}
			}
			allContracts = append(allContracts, contractsBatch...)
		}
	}

	wg := &sync.WaitGroup{}
	for _, step := range steps {
		step := step
		wg.Add(1)
		go func() {
			defer wg.Done()
			step(cache)
		}()
	}
	wg.Wait()
	if errs := cache.CheckError(); len(errs) > 0 {
		// TODO: use errors.Join when min version of go is 1.20
		// currently only first error is reported
		return nil, fmt.Errorf("failed to build cache: %w", errs[0])
	}

	cache.LinkContracts(allContracts)

	return cache, nil
}

func (c *Cache) Size() int {
	return len(c.implementationsByType)
}

func (c *Cache) PrintImplementations(w io.Writer) {
	for typString, implems := range c.implementationsByType {
		fmt.Fprintf(w, "KEY: %s\n", typString)
		for function := range implems {
			fmt.Fprintf(w, "\tFUNCTION: %s\n", function.String())
		}
	}
}

func (c *Cache) AddError(key string, e error) {
	c.errorMutex.Lock()
	defer c.errorMutex.Unlock()
	if e != nil {
		c.errors[key] = append(c.errors[key], e)
	}
}

func (c *Cache) CheckError() []error {
	c.errorMutex.Lock()
	defer c.errorMutex.Unlock()
	for e, errs := range c.errors {
		delete(c.errors, e)
		return errs
	}
	return nil
}

// PopulateTypesToImplementationMap populates the implementationsByType maps from type strings to implementations
func (c *Cache) PopulateTypesToImplementationMap() {
	if err := ComputeMethodImplementations(c.Program, c.implementationsByType, c.DataFlowContracts, c.keys); err != nil {
		c.AddError("implementationsmap", err)
	}
}

// PopulateImplementations is a verbose wrapper around PopulateTypesToImplementationsMap.
func (c *Cache) PopulateImplementations() {
	// Load information for analysis and cache it.
	c.Logger.Println("Caching information about types and functions for analysis...")
	start := time.Now()
	c.PopulateTypesToImplementationMap()
	c.Logger.Printf("Cache population terminated, added %d items (%.2f s)\n",
		c.Size(), time.Since(start).Seconds())
}

// PopulatePointerAnalysisResult populates the PointerAnalysis field of the cache by running the pointer analysis
// with queries on every function in the package such that functionFilter is true.
//
// The cache contains the result of the pointer analysis, or an error that can be inspected by CheckError
func (c *Cache) PopulatePointerAnalysisResult(functionFilter func(*ssa.Function) bool) {
	ptrResult, err := DoPointerAnalysis(c.Program, functionFilter, true)
	if err != nil {
		c.AddError("pointeranalysis", err)
	}
	c.PointerAnalysis = ptrResult
}

// PopulatePointersVerbose is a verbose wrapper around PopulatePointerAnalysisResult.
func (c *Cache) PopulatePointersVerbose(functionFilter func(*ssa.Function) bool) {
	start := time.Now()
	c.Logger.Println("Gathering values and starting pointer analysis...")
	c.PopulatePointerAnalysisResult(functionFilter)
	c.Logger.Printf("Pointer analysis terminated (%.2f s)", time.Since(start).Seconds())
}

// PopulateGlobals adds global nodes for every global defined in the program's packages
func (c *Cache) PopulateGlobals() {
	for _, pkg := range c.Program.AllPackages() {
		for _, member := range pkg.Members {
			glob, ok := member.(*ssa.Global)
			if ok {
				c.Globals[glob] = NewGlobalNode(glob)
			}
		}
	}
}

// PopulateGlobalsVerbose is a verbose wrapper around PopulateGlobals
func (c *Cache) PopulateGlobalsVerbose() {
	start := time.Now()
	c.Logger.Println("Gathering global variable declaration in the program...")
	c.PopulateGlobals()
	c.Logger.Printf("Global gathering terminated, added %d items (%.2f s)",
		len(c.Globals), time.Since(start).Seconds())
}

// PopulateBoundingInformation runs the bounding analysis
func (c *Cache) PopulateBoundingInformation(verbose bool) error {
	start := time.Now()
	if verbose {
		c.Logger.Println("Gathering information about pointer binding in closures")
	}

	boundingInfo, err := RunBoundingAnalysis(c)
	if err != nil {
		if verbose {
			c.Err.Println("Error running pointer binding analysis:")
			c.Err.Printf("  %s", err)
		}
		c.AddError("bounding analysis", err)
		return err
	} else {
		c.BoundingInfo = boundingInfo
		if verbose {
			c.Logger.Printf("Pointer binding analysis terminated, added %d items (%.2f s)",
				len(c.BoundingInfo), time.Since(start).Seconds())
		}
		return nil
	}
}

// Functions to retrieve results from the information stored in the cache

// ReachableFunctions returns the set of reachable functions according to the pointer analysis
// If the pointer analysis hasn't been run, then returns an empty map.
func (c *Cache) ReachableFunctions(excludeMain bool, excludeInit bool) map[*ssa.Function]bool {
	if c.reachableFunctions == nil {
		c.reachableFunctions = make(map[*ssa.Function]bool)
		if c.PointerAnalysis != nil {
			c.reachableFunctions = CallGraphReachable(c.PointerAnalysis.CallGraph, excludeMain, excludeInit)

		}
	}
	return c.reachableFunctions
}

// IsReachableFunction returns true if f is reachable according to the pointer analysis, or if the pointer analysis
// and ReachableFunctions has never been called.
func (c *Cache) IsReachableFunction(f *ssa.Function) bool {
	if c != nil && c.reachableFunctions != nil {
		return c.reachableFunctions[f]
	}
	// If no reachability information has been computed, assume every function is reachable
	return true
}

/* Functions for callee resolution */

// A CalleeType gives information about how the callee was resolved
type CalleeType int

const (
	Static CalleeType = 1 << iota
	CallGraph
	InterfaceContract
	InterfaceMethod
)

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
// Returns a non-nil error if it requires some information in the cache that has not been computed.
func (c *Cache) ResolveCallee(instr ssa.CallInstruction, useContracts bool) (map[*ssa.Function]CalleeInfo, error) {
	// First, check if there is a static callee
	callee := instr.Common().StaticCallee()
	if callee != nil {
		return map[*ssa.Function]CalleeInfo{callee: {Callee: callee, Type: Static}}, nil
	}

	mKey := ssafuncs.InstrMethodKey(instr)

	if useContracts {
		// If it is a method, try first to find an interface contract, and return the implementation that is used
		// in the summary of the contract.
		// Instead of considering all implementations, this means we have only one summarized implementation for
		// an interface method invocation
		if summary, ok := c.DataFlowContracts[mKey.ValueOr("")]; ok && summary != nil {
			info := CalleeInfo{Callee: summary.Parent, Type: InterfaceContract}
			return map[*ssa.Function]CalleeInfo{summary.Parent: info}, nil
		}
	}

	callees := map[*ssa.Function]CalleeInfo{}

	// Try using the callgraph from the pointer analysis
	if c.PointerAnalysis != nil {
		node, ok := c.PointerAnalysis.CallGraph.Nodes[instr.Parent()]
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
	if c.implementationsByType == nil || len(c.implementationsByType) == 0 {
		return nil, fmt.Errorf("cannot resolve callee without information about possible implementations")
	}

	if implementations, ok := c.implementationsByType[mKey.ValueOr("")]; ok {
		for implementation := range implementations {
			callees[implementation] = CalleeInfo{Callee: implementation, Type: InterfaceMethod}
		}
	}
	return callees, nil
}

/*  Functions specific to dataflow contracts stored in the cache */

// LinkContracts implements the step in the cache building function that links every dataflow contract with a specific
// SSA function. This step should only link function contracts with the SSA function, but it build the summaries for
// all contracts in allContracts.
func (c *Cache) LinkContracts(allContracts []Contract) {
	// This links the function contracts to their implementation by storing an empty summary graph in the
	// DataFlowContracts map of the cache.
	for f := range c.ReachableFunctions(false, false) {
		if _, hasContract := c.DataFlowContracts[f.String()]; hasContract {
			c.DataFlowContracts[f.String()] = NewSummaryGraph(f, GetUniqueFunctionId())
		}
	}

	// Every summary for the contract in allContracts must be built
	for _, contract := range allContracts {
		for method, methodSummary := range contract.Methods {
			c.DataFlowContracts[contract.Key(method)].
				PopulateGraphFromSummary(methodSummary, contract.InterfaceId != "")
		}
	}
}

// HasExternalContractSummary returns true if the function f has a summary has has been loaded in the DataFlowContracts
// of the cache.
func (c *Cache) HasExternalContractSummary(f *ssa.Function) bool {
	// Indirection: look for interface contract
	if interfaceMethodKey, ok := c.keys[f.String()]; ok {
		return c.DataFlowContracts[interfaceMethodKey] != nil
	}
	// Look for direct contract
	if _, ok := c.DataFlowContracts[f.String()]; ok {
		return true
	}
	return false
}

// LoadExternalContractSummary looks for contracts loaded in the DataFlowContracts of the cache.
func (c *Cache) LoadExternalContractSummary(node *CallNode) *SummaryGraph {
	if node == nil || node.callee.Callee == nil {
		return nil
	}

	// Look first for interface contracts, they have precedence over function contracts
	if isKey, methodKey := InterfaceMethodKey(node.CallSite()); isKey && node.callee.Type == InterfaceContract {
		if summary, ok := c.DataFlowContracts[methodKey]; ok {
			return summary
		}
	}

	// Look for a function contract
	if summary, ok := c.DataFlowContracts[node.callee.Callee.String()]; ok {
		return summary
	}

	return nil
}
