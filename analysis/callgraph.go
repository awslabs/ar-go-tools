// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package analysis

import (
	"fmt"
	"go/types"
	"os"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type SsaInfo struct {
	Prog     *ssa.Program
	Packages []*ssa.Package
	Mains    []*ssa.Package
}

const PkgLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedExportFile |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes |
	packages.NeedModule

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
func ComputeMethodImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool) error {
	interfaceTypes := map[*types.Interface]map[string]*types.Selection{}
	signatureTypes := map[string]bool{} // TODO: use this to index function by signature
	// Fetch all interface types
	for _, pkg := range p.AllPackages() {
		for _, mem := range pkg.Members {
			switch memType := mem.(type) {
			case *ssa.Type:
				switch iType := memType.Type().Underlying().(type) {
				case *types.Interface:
					interfaceTypes[iType] = methodSetToNameMap(p.MethodSets.MethodSet(memType.Type()))
				case *types.Signature:
					signatureTypes[iType.String()] = true
				}
			}
		}
	}

	// Fetch implementations of all interface methods
	for _, typ := range p.RuntimeTypes() {
		for interfaceType, interfaceMethods := range interfaceTypes {
			if types.Implements(typ.Underlying(), interfaceType) {
				set := p.MethodSets.MethodSet(typ)
				for i := 0; i < set.Len(); i++ {
					method := set.At(i)
					// Get the function implementation
					methodValue := p.MethodValue(method)
					// Get the interface method being implemented
					matchingInterfaceMethod := interfaceMethods[methodValue.Name()]
					if methodValue != nil && matchingInterfaceMethod != nil {
						key := matchingInterfaceMethod.Recv().String() + "." + methodValue.Name()
						addImplementation(implementations, key, methodValue)
					}
				}
			}
		}
	}
	return nil
}

func addImplementation(implementationMap map[string]map[*ssa.Function]bool, key string, function *ssa.Function) {
	if implementations, ok := implementationMap[key]; ok {
		if !implementations[function] {
			implementationMap[key][function] = true
		}
	} else {
		implementationMap[key] = map[*ssa.Function]bool{function: true}
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
