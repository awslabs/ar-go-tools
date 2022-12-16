package analysis

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"io"
	"log"
	"sync"
)

// Cache holds information that might need to be used during program analysis
type Cache struct {
	// The logger used during the analysis (can be used to control output.
	Logger *log.Logger

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

	// The result of a pointer analysis.
	PointerAnalysis *pointer.Result

	// Stored errors
	errors     map[error]bool
	errorMutex sync.Mutex
}

// NewCache returns a properly initialized cache
func NewCache(p *ssa.Program, l *log.Logger, c *config.Config) *Cache {
	return &Cache{
		Logger:                l,
		Config:                c,
		Program:               p,
		implementationsByType: map[string]map[*ssa.Function]bool{},
		PointerAnalysis:       nil,
		errors:                map[error]bool{},
	}
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
	if err := ComputeMethodImplementations(c.Program, c.implementationsByType); err != nil {
		c.AddError(err)
	}
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

//
// Functions to retrieve results from the information stored in the cache
//

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
func (c *Cache) ResolveCallee(instr ssa.CallInstruction) ([]*ssa.Function, error) {
	callee := instr.Common().StaticCallee()
	if callee != nil {
		return []*ssa.Function{callee}, nil
	}

	if c.PointerAnalysis == nil {
		return nil, fmt.Errorf("cannot resolve non-static callee without pointer analysis result")
	}

	var callees []*ssa.Function
	node, ok := c.PointerAnalysis.CallGraph.Nodes[instr.Parent()]
	if ok {
		for _, callEdge := range node.Out {
			if callEdge.Site == instr {
				callees = append(callees, callEdge.Callee.Func)
			}
		}
	}
	// If we have found the callees using the callgraph, return
	if len(callees) > 0 {
		return callees, nil
	}

	if c.implementationsByType == nil || len(c.implementationsByType) == 0 {
		return nil, fmt.Errorf("cannot resolve callee without information about possible implementations")
	}

	methodFunc := instr.Common().Method
	if methodFunc != nil {
		mInterface := instr.Common().Value
		key := mInterface.Type().String() + "." + methodFunc.Name()
		if implementations, ok := c.implementationsByType[key]; ok {
			for implementation := range implementations {
				callees = append(callees, implementation)
			}
		}
	}
	return callees, nil
}
