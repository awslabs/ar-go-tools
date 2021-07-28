// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"encoding/json"
	"fmt"
	"go/types"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"sort"
)

func findEntry(allFunctions map[*ssa.Function]bool) *ssa.Function {
	for f, _ := range allFunctions {
		if f.RelString(nil) == "command-line-arguments.main" {
			return f
		}
	}

	return nil
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

	interfaceMethods := make([]*types.Func, 0)
	findInterfaceMethods(interfaceType, &interfaceMethods)

	// turn the array into a map for fast lookup
	methodsNeeded := make(map[string]bool)

	for _, m := range interfaceMethods {
		methodsNeeded[m.Name()] = true
	}

	// get the methods of 'v.Type()'
	methodSet := program.MethodSets.MethodSet(v.Type())
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

// discover the callees of the given function, and apply the given action to these
func findCallees(program *ssa.Program, f *ssa.Function, action func(*ssa.Function)) {
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

			case *ssa.MakeInterface:
				findInterfaceCallees(program, v.Type(), v.X, action)
			}
		}
	}
}

func findReachable(program *ssa.Program) map[*ssa.Function]bool {

	allFunctions := ssautil.AllFunctions(program)

	reachable := make(map[*ssa.Function]bool)

	frontier := make([]*ssa.Function, 0)

	entry := findEntry(allFunctions)
	if entry != nil {
		frontier = append(frontier, entry)
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

func reachableFunctionsAnalysis(program *ssa.Program, jsonFlag bool) {

	reachable := findReachable(program)

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
