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
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// This file contains functions for running the pointer analysis on a program. The pointer analysis is implemented in
// the x/tools/go/pointer package.

// DoPointerAnalysis runs the pointer analysis on the program p, marking every Value in the functions filtered by
// functionFilter as potential Value to query for aliasing.
//
// - p is the program to be analyzed
//
// - functionFilter determines whether to add the values of the function in the Queries or IndirectQueries of the result
//
// - functionSet is the set of functions that will be queried.
//
// If error != nil, the *pointer.Result is such that every Value in the functions f such that functionFilter(f) is true
// will be in the Queries or IndirectQueries of the pointer.Result
func DoPointerAnalysis(c *config.Config, p *ssa.Program,
	functionFilter func(*ssa.Function) bool,
	functionSet map[*ssa.Function]bool) (*pointer.Result, error) {
	doReflection := false
	if c != nil && c.PointerConfig != nil {
		doReflection = c.PointerConfig.Reflection
	}
	pCfg := &pointer.Config{
		Mains:             ssautil.MainPackages(p.AllPackages()),
		Reflection:        doReflection,
		BuildCallGraph:    true,
		Queries:           make(map[ssa.Value]struct{}),
		IndirectQueries:   make(map[ssa.Value]struct{}),
		NoEffectFunctions: make(map[string]bool),
	}

	for function := range functionSet {
		// If the function is a user-defined function (it can be from a dependency) then every Value that can
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

			lang.IterateInstructions(function, func(_ int, instruction ssa.Instruction) {
				addInstructionQuery(pCfg, instruction)
			})
		}
	}

	if c != nil && c.PointerConfig != nil {
		for _, functionName := range c.PointerConfig.UnsafeNoEffectFunctions {
			pCfg.AddNoEffectFunction(functionName)
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
	// DebugRefs are ignored because they may cause spurious aliasing
	if _, isDebugRef := instruction.(*ssa.DebugRef); isDebugRef {
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
		// Add indirect query if Value is of pointer type, and underlying type can point
		if ptrType, ok := typ.Underlying().(*types.Pointer); ok {
			if pointer.CanPoint(ptrType.Elem()) {
				cfg.AddIndirectQuery(val)
			}
		}
	}
}
