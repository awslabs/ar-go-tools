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

package ptr

import (
	"fmt"
	"go/types"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// State extends the WholeProgramState with the pointer analysis information.
type State struct {
	*loadprogram.State

	// The pointer analysis result
	PointerAnalysis *pointer.Result

	// reachableFunctions is redefined for this state
	reachableFunctions map[*ssa.Function]bool
}

// NewState returns a pointer state that extends the whole program state passed as argument with pointer analysis
// information.
func NewState(w *loadprogram.State) result.Result[State] {
	start := time.Now()
	ps := &State{
		State:           w,
		PointerAnalysis: nil,
	}
	ps.Logger.Infof("Gathering values and starting pointer analysis...")
	reachable, err := w.ReachableFunctions()
	if err != nil {
		return result.Err[State](fmt.Errorf("error computing initial reachable functions for pointer state: %s", err))
	}
	ptrResult, err := DoPointerAnalysis(ps.Config, ps.Program, summaries.IsUserDefinedFunction, reachable)
	if err != nil {
		ps.Report.AddError("pointeranalysis", err)
	}
	if ptrResult == nil {
		return result.Err[State](fmt.Errorf("no pointer information, cannot construct pointer state"))
	}
	ps.PointerAnalysis = ptrResult
	ps.Logger.Infof("Pointer analysis terminated (%.2f s)", time.Since(start).Seconds())
	return result.Ok(ps)
}

// ReachableFunctions returns the set of reachable functions from main and init according to the pointer analysis
// callgraph.
func (s *State) ReachableFunctions() map[*ssa.Function]bool {
	if s.reachableFunctions == nil {
		s.reachableFunctions = make(map[*ssa.Function]bool)
		s.reachableFunctions = lang.CallGraphReachable(s.PointerAnalysis.CallGraph, false, false)
		return s.reachableFunctions
	}
	return s.reachableFunctions
}

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
