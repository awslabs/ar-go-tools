package dataflow

import (
	"go/types"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// This file contains functions for running the pointer analysis on a program. The pointer analysis is implemented in
// the x/tools/go/pointer package.

// DoPointerAnalysis runs the pointer analysis on the program p, marking every value in the functions filtered by
// functionFilter as potential value to query for aliasing.
//
// - p is the program to be analyzed
//
// - functionFilter determines whether to add the values of the function in the Queries or IndirectQueries of the result
//
// - buildCallGraph determines whether the analysis must also build the callgraph of the program
//
// If error != nil, the *pointer.Result is such that every value in the functions f such that functionFilter(f) is true
// will be in the Queries or IndirectQueries of the pointer.Result
func DoPointerAnalysis(p *ssa.Program, functionFilter func(*ssa.Function) bool, buildCallGraph bool) (*pointer.Result,
	error) {
	pCfg := &pointer.Config{
		Mains:           ssautil.MainPackages(p.AllPackages()),
		Reflection:      false,
		BuildCallGraph:  buildCallGraph,
		Queries:         make(map[ssa.Value]struct{}),
		IndirectQueries: make(map[ssa.Value]struct{}),
	}

	for function := range ssautil.AllFunctions(p) {
		// If the function is a user-defined function (it can be from a dependency) then every value that can
		// can potentially alias is marked for querying.
		if functionFilter(function) {
			// Add all function parameters
			for _, param := range function.Params {
				addValueQuery(pCfg, param)
			}
			// Add all free variables
			for _, fv := range function.FreeVars {
				addValueQuery(pCfg, fv)
			}

			ssafuncs.IterateInstructions(function, func(_ int, instruction ssa.Instruction) {
				addInstructionQuery(pCfg, instruction)
			})
		}
	}

	// Do the pointer analysis
	return pointer.Analyze(pCfg)
}

// addQuery adds a query for the instruction to the pointer configuration, performing all the necessary checks to
// ensure the query can be added safely.
func addInstructionQuery(cfg *pointer.Config, instruction ssa.Instruction) {
	if instruction == nil {
		return
	}

	for _, operand := range instruction.Operands([]*ssa.Value{}) {
		if *operand != nil && (*operand).Type() != nil {
			addValueQuery(cfg, *operand)
		}
	}
}

func addValueQuery(cfg *pointer.Config, value ssa.Value) {
	if value == nil {
		return
	}
	typ := value.Type()
	if pointer.CanPoint(typ) {
		cfg.AddQuery(value)
	}
	indirectQuery(cfg, typ, value)
}

// indirectQuery wraps an update to the IndirectQuery of the pointer config. We need to wrap it
// because typ.Underlying() may panic despite typ being non-nil
func indirectQuery(cfg *pointer.Config, typ types.Type, val ssa.Value) {
	defer func() {
		if r := recover(); r != nil {
			// Do nothing. Is that panic a bug? Occurs on a *ssa.opaqueType
		}
	}()

	if typ.Underlying() != nil {
		// Add indirect query if value is of pointer type, and underlying type can point
		if ptrType, ok := typ.Underlying().(*types.Pointer); ok {
			if pointer.CanPoint(ptrType.Elem()) {
				cfg.AddIndirectQuery(val)
			}
		}
	}
}
