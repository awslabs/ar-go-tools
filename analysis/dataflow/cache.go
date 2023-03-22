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

	// DataFlowContracts are dataflow graphs for interfaces.
	DataFlowContracts map[string]*SummaryGraph
	keys              map[string]string

	// The result of a pointer analysis.
	PointerAnalysis *pointer.Result

	// The global analysis
	Globals map[*ssa.Global]*GlobalNode

	// The dataflow analysis results
	FlowGraph *CrossFunctionFlowGraph

	// Stored errors
	errors     map[error]bool
	errorMutex sync.Mutex
}

// BuildFullCache runs NewCache, building all information that can be built in the cache
func BuildFullCache(logger *log.Logger, config *config.Config, program *ssa.Program) (*Cache, error) {
	program.Build()
	return NewCache(program, logger, config, []func(*Cache){
		func(cache *Cache) { cache.PopulateTypesVerbose() },
		func(cache *Cache) { cache.PopulatePointersVerbose(summaries.IsUserDefinedFunction) },
		func(cache *Cache) { cache.PopulateGlobalsVerbose() },
	})
}

// NewCache returns a properly initialized cache by running steps in parallel.
func NewCache(p *ssa.Program, l *log.Logger, c *config.Config, steps []func(*Cache)) (*Cache, error) {
	var contracts []Contract
	var err error

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
		errors: map[error]bool{},
	}
	// Link summaries to parent cache
	cache.FlowGraph.cache = cache

	// Load the dataflow contract of the interfaces from a json file if specified.
	if c.DataflowSpecs != "" {
		contracts, err = LoadDefinitions(c.RelPath(c.DataflowSpecs))
		if err != nil {
			return nil, err
		}
		if c.Verbose {
			l.Printf("Loaded dataflow contracts from %s\n", c.DataflowSpecs)
		}
		// Initialize all the entries of DataFlowContracts
		for _, contract := range contracts {
			for method := range contract.Methods {
				cache.DataFlowContracts[contract.Key(method)] = nil
			}
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
	if err := cache.CheckError(); err != nil {
		return nil, fmt.Errorf("failed to build cache: %w", err)
	}

	if c.DataflowSpecs != "" {
		for _, contract := range contracts {
			for method, methodSummary := range contract.Methods {
				cache.DataFlowContracts[contract.Key(method)].PopulateGraphFromSummary(methodSummary, true)
			}
		}
	}

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

func (c *Cache) AddError(e error) {
	c.errorMutex.Lock()
	defer c.errorMutex.Unlock()
	if e != nil {
		c.errors[e] = true
	}
}

func (c *Cache) CheckError() error {
	c.errorMutex.Lock()
	defer c.errorMutex.Unlock()
	for e := range c.errors {
		delete(c.errors, e)
		return e
	}
	return nil
}

// PopulateTypesToImplementationMap populates the implementationsByType maps from type strings to implementations
func (c *Cache) PopulateTypesToImplementationMap() {
	if err := ComputeMethodImplementations(c.Program, c.implementationsByType, c.DataFlowContracts, c.keys); err != nil {
		c.AddError(err)
	}
}

// PopulateTypesVerbose is a verbose wrapper around PopulateTypesToImplementationsMap.
func (c *Cache) PopulateTypesVerbose() {
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
		c.AddError(err)
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

// Functions to retrieve results from the information stored in the cache

// ReachableFunctions returns the set of reachable functions according to the pointer analysis
// If the pointer analysis hasn't been run, then returns an empty map.
func (c *Cache) ReachableFunctions(excludeMain bool, excludeInit bool) map[*ssa.Function]bool {
	if c.PointerAnalysis != nil {
		return CallGraphReachable(c.PointerAnalysis.CallGraph, excludeMain, excludeInit)
	} else {
		return make(map[*ssa.Function]bool)
	}
}

// Functions for callee resolution

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
func (c *Cache) ResolveCallee(instr ssa.CallInstruction) (map[*ssa.Function]CalleeInfo, error) {
	callee := instr.Common().StaticCallee()

	if callee != nil {
		return map[*ssa.Function]CalleeInfo{callee: {Callee: callee, Type: Static}}, nil
	}

	// If it is a method, try first to find an interface contract, and return the implementation that is used
	// in the summary
	mKey := ssafuncs.InstrMethodKey(instr)
	if summary, ok := c.DataFlowContracts[mKey.ValueOr("")]; ok && summary != nil {
		return map[*ssa.Function]CalleeInfo{summary.Parent: {Callee: summary.Parent, Type: InterfaceContract}}, nil
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

func (c *Cache) HasInterfaceContractSummary(f *ssa.Function) bool {
	if methodKey, ok := c.keys[f.String()]; ok {
		return c.DataFlowContracts[methodKey] != nil
	}
	return false
}

func (c *Cache) LoadInterfaceContractSummary(node *CallNode) *SummaryGraph {
	if node == nil || node.callee.Callee == nil || node.callee.Type != InterfaceContract {
		return nil
	}
	methodFunc := node.CallSite().Common().Method
	if methodFunc != nil {
		methodKey := node.CallSite().Common().Value.Type().String() + "." + methodFunc.Name()
		if summary, ok := c.DataFlowContracts[methodKey]; ok {
			return summary
		}
	}
	return nil
}
