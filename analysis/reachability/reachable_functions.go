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

package reachability

import (
	"encoding/json"
	"fmt"
	"go/types"
	"sort"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func findEntryPoints(allFunctions map[*ssa.Function]bool, excludeMain bool, excludeInit bool) []*ssa.Function {

	var entryPoints = make([]*ssa.Function, 0)

	for f := range allFunctions {

		if (!excludeMain && f.Name() == "main" && f.Pkg != nil && f.Pkg.Pkg.Name() == "main") ||
			(!excludeInit && f.Name() == "init" && f.Pkg != nil && f.Pkg.Pkg.Name() == "main") {
			entryPoints = append(entryPoints, f)
		}
	}

	return entryPoints
}

func findInterfaceMethods(interfaceType types.Type, target *[]*types.Func) {
	switch t := interfaceType.(type) {
	case *types.Named:
		findInterfaceMethods(t.Underlying(), target) // recursive call

	case *types.Interface:
		for i := 0; i < t.NumExplicitMethods(); i++ {
			m := t.ExplicitMethod(i)
			*target = append(*target, m)
		}

		for i := 0; i < t.NumEmbeddeds(); i++ {
			findInterfaceMethods(t.EmbeddedType(i), target) // recursive call
		}
	}
}

func findInterfaceCallees(program *ssa.Program, interfaceType types.Type, v ssa.Value, action func(*ssa.Function)) {

	// get the methods of 'v.Type()'
	methodSet := program.MethodSets.MethodSet(v.Type())

	// look at the methods in the interface
	interfaceMethods := make([]*types.Func, 0)
	findInterfaceMethods(interfaceType, &interfaceMethods)

	// empty, i.e., interface{}?
	if len(interfaceMethods) == 0 {
		// all methods are considered reachable
		for i := 0; i < methodSet.Len(); i++ {
			selection := methodSet.At(i)
			f := program.MethodValue(selection)
			action(f)
		}
	} else {
		// turn the array into a map for fast lookup
		methodsNeeded := make(map[string]bool, len(interfaceMethods))

		for _, m := range interfaceMethods {
			methodsNeeded[m.Name()] = true
		}

		// look at the methods of 'v.Type()'
		for i := 0; i < methodSet.Len(); i++ {
			selection := methodSet.At(i)

			// Do we need it?
			_, need := methodsNeeded[selection.Obj().Name()]
			if need {
				f := program.MethodValue(selection)
				action(f)
			}
		}
	}
}

// discover the callees of the given function, and apply the given action to these
func findCallees(program *ssa.Program, f *ssa.Function, action func(*ssa.Function)) {
	if f == nil {
		return
	}
	// look for functions that are called
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			switch v := instr.(type) {
			case *ssa.Call:
			case *ssa.Defer:
			case *ssa.Go:

				// invoke?
				if v.Call.IsInvoke() {
					// We invoke a method via an interface.
					// This is covered by 'MakeInterface' below.
				} else {
					switch value := v.Call.Value.(type) {
					case *ssa.Function:
						action(value)

					case *ssa.MakeClosure:
						if fn, ok := value.Fn.(*ssa.Function); ok {
							action(fn)
						}

					}
				}

			case *ssa.MakeInterface:
				findInterfaceCallees(program, v.Type(), v.X, action)
			}
		}
	}

	// look for functions whose address is taken
	seen := make(map[ssa.Value]bool)

	valueAction := func(v ssa.Value) {
		if x, ok := v.(*ssa.Function); ok {
			action(x)
		}
	}

	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			preTraversalVisitValuesInstruction(instr, seen, valueAction)
		}
	}
}

// FindReachable traverses the call graph starting from the given entry
// points to find all reachable functions.
//
// It takes a program, a flag for whether to exclude the main function, a
// flag for whether to exclude init functions, and an optional dependency
// graph to record cross-package function calls.
//
// The return value is a map from reachable *ssa.Function values to true.
func FindReachable(state *loadprogram.State, excludeMain bool, excludeInit bool, graph DependencyGraph) map[*ssa.Function]bool {

	allFunctions := ssautil.AllFunctions(state.Program)
	state.Logger.Infof("%d SSA functions\n", len(allFunctions))

	reachable := make(map[*ssa.Function]bool, len(allFunctions))

	frontier := make([]*ssa.Function, 0)

	entryPoints := findEntryPoints(allFunctions, excludeMain, excludeInit)
	state.Logger.Infof("%d entrypoints\n", len(entryPoints))
	for _, f := range entryPoints {
		reachable[f] = true
		frontier = append(frontier, f)
	}

	// compute the fixedpoint
	for len(frontier) != 0 {
		f := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		findCallees(state.Program, f, func(fnext *ssa.Function) {
			if graph != nil {
				from := lang.PackageNameFromFunction(f)
				to := lang.PackageNameFromFunction(fnext)
				if from != to && from != "" {
					graph.Add(from, to)
				}
			}

			if !reachable[fnext] {
				reachable[fnext] = true
				frontier = append(frontier, fnext)
			}
		})
	}
	state.Logger.Infof("%d reachable functions\n", len(reachable))

	return reachable
}

// ReachableFunctionsAnalysis runs the reachable function analysis. Main and Init can be excluded using the
// boolean flags. The analysis prints the reachable functions on standard output.
//
// TODO: make it parametric on a state with a callgraph interface
func ReachableFunctionsAnalysis(state *loadprogram.State, excludeMain bool, excludeInit bool, jsonFlag bool) {
	reachable := FindReachable(state, excludeMain, excludeInit, nil)

	functionNames := make([]string, 0, len(reachable))

	for f := range reachable {
		functionNames = append(functionNames, f.RelString(nil))
	}

	// sort alphabetically by name
	sort.Slice(functionNames, func(i, j int) bool {
		return functionNames[i] < functionNames[j]
	})

	if jsonFlag {
		buf, _ := json.Marshal(functionNames)
		fmt.Println(string(buf))
	} else {
		for _, name := range functionNames {
			fmt.Printf("%s\n", formatutil.Sanitize(name))
		}
	}
}
