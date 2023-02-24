// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package dataflow

import (
	"fmt"
	"go/types"
	"os"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type SsaInfo struct {
	Prog     *ssa.Program
	Packages []*ssa.Package
	Mains    []*ssa.Package
}

type CallgraphAnalysisMode uint64

const (
	PointerAnalysis        CallgraphAnalysisMode = iota // PointerAnalysis is over-approximating (slow)
	StaticAnalysis                                      // StaticAnalysis is under-approximating (fast)
	ClassHierarchyAnalysis                              // ClassHierarchyAnalysis is a coarse over-approximation (fast)
	RapidTypeAnalysis                                   // RapidTypeAnalysis TODO: review
	VariableTypeAnalysis                                // VariableTypeAnalysis TODO: review
)

// ComputeCallgraph computes the call graph of prog using the provided mode.
func (mode CallgraphAnalysisMode) ComputeCallgraph(prog *ssa.Program) (*callgraph.Graph, error) {
	switch mode {
	case PointerAnalysis:
		// Build the callgraph using the pointer analysis. This function returns only the
		// callgraph, and not the entire pointer analysis result.
		// Pointer analysis is using Andersen's analysis. The documentation claims that
		// the analysis is sound if the program does not use reflection or unsafe Go.
		result, err := DoPointerAnalysis(prog, func(_ *ssa.Function) bool { return false }, true)
		if err != nil { // not a user-input problem if it fails, see Analyze doc.
			return nil, fmt.Errorf("pointer analysis failed: %w", err)
		}
		return result.CallGraph, nil
	case StaticAnalysis:
		// Build the callgraph using only static analysis.
		return static.CallGraph(prog), nil
	case ClassHierarchyAnalysis:
		// Build the callgraph using the Class Hierarchy Analysis
		// See the documentation, and
		// "Optimization of Object-Oriented Programs Using Static Class Hierarchy Analysis",
		// J. Dean, D. Grove, and C. Chambers, ECOOP'95.
		return cha.CallGraph(prog), nil
	case VariableTypeAnalysis:
		// Need to review how to use variable type analysis properly
		roots := make(map[*ssa.Function]bool)
		mains := ssautil.MainPackages(prog.AllPackages())
		for _, m := range mains {
			// Look at all init and main functions in main packages
			roots[m.Func("init")] = true
			roots[m.Func("main")] = true
		}
		cg := static.CallGraph(prog)
		return vta.CallGraph(roots, cg), nil
	case RapidTypeAnalysis:
		// Build the callgraph using rapid type analysis
		// See the documentation, and
		// "Fast Analysis of C++ Virtual Function Calls", D.Bacon & P. Sweeney, OOPSLA'96
		var roots []*ssa.Function
		mains := ssautil.MainPackages(prog.AllPackages())
		for _, m := range mains {
			// Start at all init and main functions in main packages
			roots = append(roots, m.Func("init"), m.Func("main"))
		}
		return rta.Analyze(roots, true).CallGraph, nil
	default:
		fmt.Fprint(os.Stderr, "Unsupported callgraph analysis mode.")
		return nil, nil
	}
}

// ComputeMethodImplementations populates a map from method implementation type string to the different implementations
// corresponding to that method.
// The map can be indexed by using the signature of an interface method and calling String() on it.
// If the provided contracts map is non-nil, then the function also builds a summary graph for each interface
// method such that contracts[methodId] = nil
func ComputeMethodImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool,
	contracts map[string]*SummaryGraph, keys map[string]string) error {
	interfaceTypes := map[*ssa.Type]map[string]*types.Selection{}
	signatureTypes := map[string]bool{} // TODO: use this to index function by signature
	// Fetch all interface types
	for _, pkg := range p.AllPackages() {
		for _, mem := range pkg.Members {
			switch memType := mem.(type) {
			case *ssa.Type:
				switch iType := memType.Type().Underlying().(type) {
				case *types.Interface:
					interfaceTypes[memType] = methodSetToNameMap(p.MethodSets.MethodSet(memType.Type()))
				case *types.Signature:
					signatureTypes[iType.String()] = true
				}
			}
		}
	}

	// Fetch implementations of all interface methods

	for interfaceType, interfaceMethods := range interfaceTypes {
		for _, typ := range p.RuntimeTypes() {
			// Find the interfaces it implements (type conversion cannot fail)
			if types.Implements(typ.Underlying(), interfaceType.Type().Underlying().(*types.Interface)) {
				set := p.MethodSets.MethodSet(typ)
				for i := 0; i < set.Len(); i++ {
					method := set.At(i)
					// Get the function implementation
					methodValue := p.MethodValue(method)
					// Get the interface method being implemented
					matchingInterfaceMethod := interfaceMethods[methodValue.Name()]
					if methodValue != nil && matchingInterfaceMethod != nil {
						key := matchingInterfaceMethod.Recv().String() + "." + methodValue.Name()
						keys[methodValue.String()] = key
						addImplementation(implementations, key, methodValue)
						addContractSummaryGraph(contracts, key, methodValue)
					}
				}
			}
		}
	}

	computeErrorBuiltinImplementations(p, implementations, contracts, keys)

	return nil
}

// computeErrorBuiltinImplementations adds the implementations of the builtin error interface (the error.Error method)
// to the implementations map
func computeErrorBuiltinImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool,
	contracts map[string]*SummaryGraph, keys map[string]string) {
	key := "error.Error"
	for _, typ := range p.RuntimeTypes() {
		set := p.MethodSets.MethodSet(typ)
		// Does it implement the error builtin?
		for i := 0; i < set.Len(); i++ {
			method := set.At(i)
			// Get the function implementation
			methodValue := p.MethodValue(method)
			if methodValue.Name() != "Error" || len(methodValue.Params) > 1 {
				continue
			}
			results := methodValue.Signature.Results()
			if results.Len() != 1 {
				continue
			}
			expectedString := results.At(0).Type().Underlying()
			if expectedString.String() != "string" {
				continue
			}

			keys[methodValue.String()] = key
			// Get the interface method being implemented
			addImplementation(implementations, key, methodValue)
			addContractSummaryGraph(contracts, key, methodValue)
		}
	}
}

// addImplementation sets the value of key in implementationsMap to function, handling the creation of nested maps.
// @requires implementationMap != nil
func addImplementation(implementationMap map[string]map[*ssa.Function]bool, key string, function *ssa.Function) {
	if implementations, ok := implementationMap[key]; ok {
		if !implementations[function] {
			implementationMap[key][function] = true
		}
	} else {
		implementationMap[key] = map[*ssa.Function]bool{function: true}
	}
}

// addContractSummaryGraph sets the value of contract[methodId] to a new summary of function if the methodId key
// is present in contracts but the associated value is nil
// Does nothing if contracts is nil.
func addContractSummaryGraph(contracts map[string]*SummaryGraph, methodId string, function *ssa.Function) {
	if contracts == nil || function == nil {
		return
	}
	// Entry must be present
	if curSummary, ok := contracts[methodId]; ok {
		if curSummary == nil {
			contracts[methodId] = NewSummaryGraph(function)
		}
	}
}

func methodSetToNameMap(methodSet *types.MethodSet) map[string]*types.Selection {
	nameMap := map[string]*types.Selection{}

	for i := 0; i < methodSet.Len(); i++ {
		method := methodSet.At(i)
		nameMap[method.Obj().Name()] = method
	}
	return nameMap
}

// CallGraphReachable returns a map where each entry is a reachable function
func CallGraphReachable(cg *callgraph.Graph, excludeMain bool, excludeInit bool) map[*ssa.Function]bool {
	entryPoints := findCallgraphEntryPoints(cg, excludeMain, excludeInit)

	reachable := make(map[*ssa.Function]bool, len(cg.Nodes))

	frontier := make([]*callgraph.Node, 0)

	for _, node := range entryPoints {
		//	node := cg.Root
		reachable[node.Func] = true
		frontier = append(frontier, node)
	}

	for len(frontier) != 0 {
		node := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, edge := range node.Out {
			if !reachable[edge.Callee.Func] {
				reachable[edge.Callee.Func] = true
				frontier = append(frontier, edge.Callee)
			}
		}
	}

	return reachable
}

func findCallgraphEntryPoints(cg *callgraph.Graph, excludeMain bool, excludeInit bool) []*callgraph.Node {
	entryPoints := make([]*callgraph.Node, 0)
	for f, node := range cg.Nodes {
		if f == nil {
			continue
		}
		var name = f.String()

		if (!excludeMain && name == "command-line-arguments.main") ||
			(!excludeInit && name == "command-line-arguments.init") {
			entryPoints = append(entryPoints, node)
		}
	}
	return entryPoints
}
