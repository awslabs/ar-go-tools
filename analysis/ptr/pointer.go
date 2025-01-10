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
	"go/token"
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

// AliasCache represents a "global" cache for transitive pointers and aliases.
//
// The analysis only searches for pointers and aliases that are reachable from a
// single entrypoint, but this cache helps if there are multiple entrypoints
// that need alias information computed from previous entrypoints.
type AliasCache struct {
	PtrState       *State
	ReachableFuncs map[*ssa.Function]bool
	ObjectPointees map[ssa.Value]map[*pointer.Object]struct{}
}

// NewAliasCache returns an empty alias cache from state.
func NewAliasCache(state *State) *AliasCache {
	return &AliasCache{
		PtrState:       state,
		ReachableFuncs: state.ReachableFunctions(),
		ObjectPointees: make(map[ssa.Value]map[*pointer.Object]struct{}),
	}
}

// Objects returns all the unique Objects that val points to.
func (ac *AliasCache) Objects(val ssa.Value) map[*pointer.Object]struct{} {
	if mi, ok := val.(*ssa.MakeInterface); ok {
		// if val is an interface, the object is the concrete struct
		val = mi.X
	}
	if res, ok := ac.ObjectPointees[val]; ok && len(res) > 0 {
		return res
	}

	ptrs := findAllPointers(ac.PtrState.PointerAnalysis, val)
	if len(ptrs) == 0 {
		return nil
	}

	res := make(map[*pointer.Object]struct{}, len(ptrs))
	for _, ptr := range ptrs {
		for _, label := range ptr.PointsTo().Labels() {
			obj := label.Obj()
			if obj == nil {
				continue
			}

			// Skip allocated context.Context and error objects since we assume
			// that they are used as values
			switch data := obj.Data().(type) {
			case *ssa.Alloc:
				switch data.Type().String() {
				case "*error", "*context.Context":
					continue
				}
			}

			res[obj] = struct{}{}
		}
	}

	ac.ObjectPointees[val] = res
	return res
}

// findAllPointers returns all the pointers that point to v.
func findAllPointers(res *pointer.Result, v ssa.Value) []pointer.Pointer {
	var allptr []pointer.Pointer
	if ptr, ptrExists := res.Queries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	// By indirect query
	// if ptr, ptrExists := res.IndirectQueries[v]; ptrExists {
	// 	allptr = append(allptr, ptr)
	// }
	return allptr
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

// Write is an instruction that writes to an entrypoint's underlying memory.
type Write struct {
	ssa.Instruction
	Target ssa.Value // Target is the value written to.
	Value  ssa.Value // Value is the value that is written.
	Pos    token.Position
}

func (w Write) String() string {
	return fmt.Sprintf("write to %v with %v at %v", w.Target, w.Value, w.Pos)
}

// Read is an instruction that reads from an entrypoint's underlying memory.
type Read struct {
	ssa.Instruction
	Values []ssa.Value // Values are the values that are read from.
	Pos    token.Position
}

func (r Read) String() string {
	return fmt.Sprintf("read of %v at %v", r.Values, r.Pos)
}

// PtrWrittenTo returns true if instruction writes a scalar value to a pointer
// value.
func PtrWrittenTo(instr ssa.Instruction, pos token.Position) (Write, bool) {
	var lval ssa.Value
	var rval ssa.Value
	switch instr := instr.(type) {
	case *ssa.Store:
		lval = instr.Addr
		rval = instr.Val
	case *ssa.MapUpdate:
		lval = instr.Map
		rval = instr.Value
	case *ssa.Send:
		lval = instr.Chan
		rval = instr.X
	default:
		return Write{}, false
	}

	if instr.Parent() == nil {
		return Write{}, false
	}
	pkg := instr.Parent().Pkg
	// we assume that errors are never used as pointer values
	if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "errors" {
		return Write{}, false
	}

	if !pointer.CanPoint(rval.Type()) && pointer.CanPoint(lval.Type()) {
		return Write{Instruction: instr, Target: lval, Value: rval, Pos: pos}, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" && !pointer.CanPoint(rval.Type()) {
				return Write{Instruction: instr, Target: lval, Value: rval, Pos: pos}, true
			}
		}
	}

	return Write{}, false
}

// PtrWrittenToPtr returns true if instruction writes a pointer value to a pointer
// value.
//
// TODO refactor to reduce duplication
//
//gocyclo:ignore
func PtrWrittenToPtr(instr ssa.Instruction, pos token.Position) (Write, bool) {
	var lval ssa.Value
	var rval ssa.Value
	switch instr := instr.(type) {
	case *ssa.Store:
		lval = instr.Addr
		rval = instr.Val
	case *ssa.MapUpdate:
		lval = instr.Map
		rval = instr.Value
	case *ssa.Send:
		lval = instr.Chan
		rval = instr.X
	default:
		return Write{}, false
	}

	if instr.Parent() == nil {
		return Write{}, false
	}
	pkg := instr.Parent().Pkg
	// we assume that errors are never used as pointer values
	if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "errors" {
		return Write{}, false
	}

	if pointer.CanPoint(rval.Type()) && pointer.CanPoint(lval.Type()) {
		switch rval := rval.(type) {
		case *ssa.ChangeInterface:
			// Special case for: e.g. change interface interface{} <- error
			// we assume that errors are never used as pointer values
			if rval.X.Type().String() == "error" {
				return Write{}, false
			}
		case *ssa.Call:
			// Special case for: e.g. fmt.Errorf(...) where the return type is an error
			if rval.Type().String() == "error" {
				return Write{}, false
			}
		}

		return Write{Instruction: instr, Target: lval, Value: rval, Pos: pos}, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" && pointer.CanPoint(rval.Type()) {
				return Write{Instruction: instr, Target: lval, Value: rval, Pos: pos}, true
			}
		}
	}

	return Write{}, false
}

// PtrsReadFrom returns a read instruction containing all the pointer values
// read from instruction.
//
//gocyclo:ignore
func PtrsReadFrom(instr ssa.Instruction, pos token.Position) (Read, bool) {
	var rvals []ssa.Value
	add := func(vs ...ssa.Value) {
		for _, v := range vs {
			if v == nil {
				continue
			}

			if pointer.CanPoint(v.Type()) {
				rvals = append(rvals, v)
			}
		}
	}

	switch instr := instr.(type) {
	case *ssa.Call:
		if _, ok := instr.Call.Value.(*ssa.Builtin); ok {
			add(instr.Call.Args...)
		}
	case *ssa.Index:
		add(instr.X)
	case *ssa.Lookup:
		add(instr.X, instr.Index)
	case *ssa.Slice:
		add(instr.X)
	case *ssa.UnOp:
		// Dereference y = *x
		if instr.Op == token.MUL {
			add(instr.X)
		}
		// Channel receive y <- x
		if instr.Op == token.ARROW {
			add(instr.X)
		}
	}

	if len(rvals) == 0 {
		return Read{Instruction: instr, Values: nil, Pos: pos}, false
	}

	return Read{Instruction: instr, Values: rvals, Pos: pos}, true
}
