// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package reachability

import (
	"encoding/json"
	"fmt"
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func findEntryPoints(allFunctions map[*ssa.Function]bool) []*ssa.Function {

	var entryPoints = make([]*ssa.Function, 0)

	for f, _ := range allFunctions {
		var name = f.RelString(nil)
		if name == "command-line-arguments.main" || name == "command-line-arguments.init" {
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
		methodsNeeded := make(map[string]bool)

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

	// look for functions that are called
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			switch v := instr.(type) {
			case *ssa.Call:
				// invoke?
				if v.Call.IsInvoke() {
					// We invoke a method via an interface.
					// This is covered by 'MakeInterface' below.
				} else {
					switch value := v.Call.Value.(type) {
					case *ssa.Function:
						action(value)

					case *ssa.MakeClosure:
						switch fn := value.Fn.(type) {
						case *ssa.Function:
							action(fn)
						}
					}
				}

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
						switch fn := value.Fn.(type) {
						case *ssa.Function:
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
		switch x := v.(type) {

		case *ssa.Function:
			action(x)
		}
	}

	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			preTraversalVisitValuesInstruction(instr, &seen, valueAction)
		}
	}
}

func FindReachable(program *ssa.Program) map[*ssa.Function]bool {

	allFunctions := ssautil.AllFunctions(program)

	reachable := make(map[*ssa.Function]bool)

	frontier := make([]*ssa.Function, 0)

	entryPoints := findEntryPoints(allFunctions)
	for _, f := range entryPoints {
		frontier = append(frontier, f)
	}

	// compute the fixedpoint
	for len(frontier) != 0 {
		f := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		reachable[f] = true
		findCallees(program, f, func(fnext *ssa.Function) {
			_, ok := reachable[fnext]
			if !ok {
				frontier = append(frontier, fnext)
			}
		})
	}

	return reachable
}

func ReachableFunctionsAnalysis(program *ssa.Program, jsonFlag bool) {

	reachable := FindReachable(program)

	functionNames := make([]string, 0, len(reachable))

	for f, _ := range reachable {
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
			fmt.Printf("%s\n", name)
		}
	}
}
