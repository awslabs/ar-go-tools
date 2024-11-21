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

package lang

import (
	"fmt"
	"os"

	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// CallgraphAnalysisMode is either PointerAnalysis, StaticAnalysis, ClassHierarchyAnalysis, RapidTypeAnalysis or
// VariableTypeAnalysis for calling ComputeCallGraph
type CallgraphAnalysisMode uint64

const (
	// PointerAnalysis is over-approximating (slow)
	PointerAnalysis CallgraphAnalysisMode = iota
	// StaticAnalysis is under-approximating (fast)
	StaticAnalysis
	// ClassHierarchyAnalysis is a coarse over-approximation (fast)
	ClassHierarchyAnalysis
	// RapidTypeAnalysis TODO: review
	RapidTypeAnalysis
	// VariableTypeAnalysis TODO: review
	VariableTypeAnalysis
)

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

// ComputeCallgraph computes the call graph of prog using the provided mode.
func (mode CallgraphAnalysisMode) ComputeCallgraph(prog *ssa.Program) (*callgraph.Graph, error) {
	switch mode {
	case PointerAnalysis:
		// Build the callgraph using the pointer analysis. This function returns only the
		// callgraph, and not the entire pointer analysis result.
		// Pointer analysis is using Andersen's analysis. The documentation claims that
		// the analysis is sound if the program does not use reflection or unsafe Go.
		pCfg := &pointer.Config{
			Mains:             ssautil.MainPackages(prog.AllPackages()),
			Reflection:        true,
			BuildCallGraph:    true,
			Queries:           make(map[ssa.Value]struct{}),
			IndirectQueries:   make(map[ssa.Value]struct{}),
			NoEffectFunctions: make(map[string]bool),
		}
		result, err := pointer.Analyze(pCfg)
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

// CallGraphReachable returns a map where each entry is a reachable function
func CallGraphReachable(cg *callgraph.Graph, excludeMain bool, excludeInit bool) map[*ssa.Function]bool {
	if cg == nil {
		return nil
	}
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
		if (node.ID != 0) &&
			((!excludeMain && f.Name() == "main" && f.Pkg != nil && f.Pkg.Pkg.Name() == "main") ||
				(!excludeInit && f.Name() == "init" && f.Pkg != nil && f.Pkg.Pkg.Name() == "main")) {
			entryPoints = append(entryPoints, node)
		}
	}
	return entryPoints
}
