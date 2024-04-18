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

// Package modptr implements an analysis that detects all modifications to a pointer-like value.
package modptr

import (
	"errors"
	"fmt"
	"go/token"
	"strconv"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Result represents the result of the analysis.
type Result struct {
	// Modifications represents the instructions that modify the entrypoint.
	Modifications map[Entrypoint]map[ssa.Instruction]struct{}
}

// Entrypoint represents an Entrypoint.
type Entrypoint struct {
	// Val is the argument value.
	Val ssa.Value
	// Call is the call instruction containing the argument.
	Call ssa.CallInstruction
	// Pos is the position of the callsite, not the argument value itself.
	Pos token.Position
}

// Analyze runs the analysis on prog.
func Analyze(cfg *config.Config, lp analysis.LoadedProgram, ptrRes *pointer.Result) (Result, error) {
	modifications := map[Entrypoint]map[ssa.Instruction]struct{}{}
	prog := lp.Program
	log := config.NewLogGroup(cfg)

	reachable := ssautil.AllFunctions(prog)
	// reachable := lang.CallGraphReachable(ptrRes.CallGraph, false, false)
	allInstrs := allInstrs(reachable)
	allVals := allValues(reachable)
	pv := progVals{
		prog:             prog,
		ptrRes:           ptrRes,
		allInstrs:        allInstrs,
		allValues:        allVals,
		reachableFuncs:   reachable,
		transitivePtrsTo: make(map[ssa.Value][]pointer.Pointer, len(allVals)),
		aliasesOf:        make(map[pointer.Pointer]map[ssa.Value]struct{}),
	}

	var errs []error
	for _, spec := range cfg.ModificationTrackingProblems {
		if err := analyze(log, spec, pv, modifications); err != nil {
			errs = append(errs, fmt.Errorf("analysis failed for spec %v: %v", spec, err))
		}
	}

	return Result{
		Modifications: modifications,
	}, errors.Join(errs...)
}

// analyze runs the analysis for a single spec and adds the write instructions to modifications.
func analyze(log *config.LogGroup, spec config.ModValSpec, pv progVals, modifications map[Entrypoint]map[ssa.Instruction]struct{}) error {
	reachable := pv.reachableFuncs
	prog := pv.prog
	ptrRes := pv.ptrRes
	shouldFilter := func(spec config.ModValSpec, val ssa.Value) bool {
		return val == nil || isConfigFiltered(spec, val.Parent())
	}
	filterFn := func(fn *ssa.Function) bool {
		if isPure(fn) {
			return true
		}

		return isConfigFiltered(spec, fn)
	}

	var errs []error
	entrypoints := findEntrypoints(prog, reachable, spec, ptrRes)
	for entry := range entrypoints {
		val := entry.Val
		if !pointer.CanPoint(val.Type()) {
			errs = append(errs, fmt.Errorf("entrypoint is a non-pointer type: %v", val.Type()))
			continue
		}
		parent := val.Parent()
		// only analyze the functions that are reachable from the function that
		// calls the entrypoint and are not pure.
		reachableFns := lang.ReachableFrom(ptrRes.CallGraph, parent, filterFn)
		reachableVals := allValues(reachableFns)
		reachableInstrs := allInstrs(reachableFns)

		log.Infof("ENTRY: %v of %v in %v at %v\n", val.Name(), entry.Call, val.Parent(), entry.Pos)
		log.Debugf("\tnumber of reachable vals: %v\n", len(reachableVals))
		s := &state{
			progVals:                 pv,
			log:                      log,
			spec:                     spec,
			writesToAlias:            make(map[ssa.Value]map[ssa.Instruction]struct{}),
			filterValue:              shouldFilter,
			valsReachableFromEntry:   reachableVals,
			instrsReachableFromEntry: reachableInstrs,
		}
		ptrs := s.progVals.transitivePointersTo(val)
		s.findWritesToAliases(ptrs)
		for _, instrs := range s.writesToAlias {
			for instr := range instrs {
				if _, ok := modifications[entry]; !ok {
					modifications[entry] = make(map[ssa.Instruction]struct{})
				}

				modifications[entry][instr] = struct{}{}
			}
		}
	}

	return errors.Join(errs...)
}

// state represents the analysis state.
// This tracks writes to a single value (entrypoint).
type state struct {
	progVals
	log  *config.LogGroup
	spec config.ModValSpec

	instrsReachableFromEntry map[ssa.Instruction]struct{}
	valsReachableFromEntry   map[ssa.Value]struct{}
	// filterValue returns true if the value should be filtered
	// according to the spec.
	filterValue func(config.ModValSpec, ssa.Value) bool
	// writesToAlias stores the set of instructions that write to an alias
	// (SSA value).
	writesToAlias map[ssa.Value]map[ssa.Instruction]struct{}
}

// findWritesToAliases adds all write instructions to transitive aliases of
// ptrs to s.writesToAlias.
//
// Algorithm:
//  1. Compute all values that transitively may-alias ptrs, considering every
//     value in the program, not just the values reachable from ptrs.
//     We need to compute *all* the possible aliases because some pointers will
//     not be reachable from an entrypoint, but one of the pointers that point
//     to it may be.
//     This initializes the global may-alias cache.
//  2. Filter all may-aliased values that are not reachable from the entrypoint
//     or are not needed because of the spec.
//  3. For every instruction reachable from the entrypoint, if the lvalue is an
//     alias, or the instruction allocates a value to an alias, then the alias
//     has been "modified".
func (s *state) findWritesToAliases(ptrs []pointer.Pointer) {
	log := s.log
	for _, ptr := range ptrs {
		allAliases := make(map[ssa.Value]struct{})
		s.progVals.allAliasesOf(ptr, allAliases)
		for alias := range allAliases {
			if _, ok := s.valsReachableFromEntry[alias]; !ok {
				delete(allAliases, alias)
			}
			if s.filterValue(s.spec, alias) {
				log.Tracef("alias %v filtered by spec\n", alias)
				delete(allAliases, alias)
			}
			// special case: *ssa.MakeInterface aliases rvalue
			if mi, ok := alias.(*ssa.MakeInterface); ok {
				allAliases[mi.X] = struct{}{}
			}
		}
		for alias := range allAliases {
			s.addTransitiveMayAliases(alias, allAliases)
		}

		for alias := range allAliases {
			log.Tracef("alias %v: %v in %v\n", alias.Name(), alias, alias.Parent())
			if _, ok := s.writesToAlias[alias]; !ok {
				s.writesToAlias[alias] = make(map[ssa.Instruction]struct{})
			}

			for instr := range s.instrsReachableFromEntry {
				allocs := false
				if alloc, ok := instr.(*ssa.Alloc); ok {
					allocs = alloc == alias
				}

				if _, ok := lang.InstrWritesToVal(instr, alias); ok || allocs {
					log.Tracef("instr %v writes to alias %v\n", instr, alias)
					s.writesToAlias[alias][instr] = struct{}{}
				}
			}
		}
	}
}

// addTransitiveMayAliases adds all transitive aliases of alias to allAliases.
func (s *state) addTransitiveMayAliases(alias ssa.Value, allAliases map[ssa.Value]struct{}) {
	visit := s.progVals.transitivePointersTo(alias)
	seen := make(map[pointer.Pointer]struct{})
	for len(visit) > 0 {
		cur := visit[len(visit)-1]
		visit = visit[0 : len(visit)-1]
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		newAliases := make(map[ssa.Value]struct{})
		s.progVals.allAliasesOf(cur, newAliases)
		for a := range newAliases {
			if _, ok := allAliases[a]; ok || s.filterValue(s.spec, a) {
				continue
			}
			if _, ok := s.valsReachableFromEntry[a]; !ok {
				continue
			}

			allAliases[a] = struct{}{}
			s.log.Tracef("found transitive alias of %v: %v (%v) in %v\n", alias, a, a.Name(), a.Parent())
			for _, next := range s.progVals.transitivePointersTo(a) {
				visit = append(visit, next)
			}
		}
	}
}

// progVals contains all the usable SSA instructions/values in the program used
// for the analysis.
type progVals struct {
	prog           *ssa.Program
	ptrRes         *pointer.Result
	allInstrs      map[ssa.Instruction]struct{}
	allValues      map[ssa.Value]struct{}
	reachableFuncs map[*ssa.Function]bool
	// transitivePtrsTo stores the set of transitive pointers to a value.
	transitivePtrsTo map[ssa.Value][]pointer.Pointer
	// aliasesOf stores the set of values that are in the points-to set of a pointer.
	aliasesOf map[pointer.Pointer]map[ssa.Value]struct{}
}

func (pv *progVals) transitivePointersTo(val ssa.Value) []pointer.Pointer {
	if p, ok := pv.transitivePtrsTo[val]; ok {
		return p
	}

	stack := lang.FindAllPointers(pv.ptrRes, val)
	seen := make(map[pointer.Pointer]struct{})
	var ptrs []pointer.Pointer
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		for _, label := range cur.PointsTo().Labels() {
			val := label.Value()
			if val == nil || val.Parent() == nil {
				continue
			}

			labelPtrs := lang.FindAllPointers(pv.ptrRes, val)
			stack = append(stack, labelPtrs...)
			for _, ptr := range labelPtrs {
				ptrs = append(ptrs, ptr)
			}
		}
	}

	pv.transitivePtrsTo[val] = ptrs
	return ptrs
}

func (pv *progVals) allAliasesOf(ptr pointer.Pointer, aliases map[ssa.Value]struct{}) {
	if a, ok := pv.aliasesOf[ptr]; ok && len(a) > 0 {
		for v := range a {
			aliases[v] = struct{}{}
		}

		return
	}

	for val := range pv.allValues {
		if _, ok := aliases[val]; ok {
			continue
		}

		ptrs := pv.transitivePointersTo(val)
		for _, valPtr := range ptrs {
			if valPtr.MayAlias(ptr) {
				aliases[val] = struct{}{}
			}
		}
	}

	pv.aliasesOf[ptr] = aliases
}

func allInstrs(fns map[*ssa.Function]bool) map[ssa.Instruction]struct{} {
	res := make(map[ssa.Instruction]struct{})
	for fn := range fns {
		lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
			if instr == nil || instr.Parent() == nil {
				return
			}

			res[instr] = struct{}{}
		})
	}

	return res
}

func allValues(fns map[*ssa.Function]bool) map[ssa.Value]struct{} {
	res := make(map[ssa.Value]struct{})
	for fn := range fns {
		if fn == nil {
			continue
		}

		lang.IterateValues(fn, func(_ int, val ssa.Value) {
			if val == nil || val.Parent() == nil {
				return
			}

			res[val] = struct{}{}
		})
	}

	return res
}

func findEntrypoints(prog *ssa.Program, reachable map[*ssa.Function]bool, spec config.ModValSpec, ptrRes *pointer.Result) map[Entrypoint]struct{} {
	entrypoints := make(map[Entrypoint]struct{})
	for fn, node := range ptrRes.CallGraph.Nodes {
		if fn == nil {
			continue
		}
		if _, ok := reachable[fn]; !ok {
			continue
		}

		for _, inEdge := range node.In {
			if inEdge == nil || inEdge.Site == nil {
				continue
			}

			entry, ok := findEntrypoint(prog, ptrRes, spec, inEdge.Site.Value())
			if !ok {
				continue
			}

			entrypoints[entry] = struct{}{}
		}
	}

	return entrypoints
}

func findEntrypoint(prog *ssa.Program, ptrRes *pointer.Result, spec config.ModValSpec, call *ssa.Call) (Entrypoint, bool) {
	// use analysisutil entrypoint logic to take care of function aliases and
	// other edge-cases
	if !analysisutil.IsEntrypointNode(ptrRes, call, spec.IsValue) {
		return Entrypoint{}, false
	}

	callPos := prog.Fset.Position(call.Pos())
	for _, cid := range spec.Values {
		// TODO parse label beforehand to prevent panics
		idx, err := strconv.Atoi(cid.Label)
		if err != nil {
			err := fmt.Errorf("cid label is not a valid argument index: %v", err)
			panic(err)
		}
		if idx < 0 {
			err := fmt.Errorf("cid label is not a valid argument index: %v < 0", idx)
			panic(err)
		}

		args := lang.GetArgs(call)
		if len(args) < idx {
			fmt.Printf("arg index: %v < want %v\n", len(args), idx)
			return Entrypoint{}, false
		}

		val := args[idx]
		return Entrypoint{Val: val, Call: call, Pos: callPos}, true
	}

	return Entrypoint{}, false
}

// isPure returns true if no instruction in the body of function f can modify an
// outside value, or the function does not return a pointer.
//
// We assume that the analysis is not tracking modifications to a global value.
func isPure(f *ssa.Function) bool {
	if _, ok := pureFunctions[f.String()]; ok {
		return true
	}

	for _, param := range f.Params {
		if pointer.CanPoint(param.Type()) {
			return false
		}
	}

	for _, fv := range f.FreeVars {
		if pointer.CanPoint(fv.Type()) {
			return false
		}
	}

	results := f.Signature.Results()
	for i := 0; i < results.Len(); i++ {
		ret := results.At(i)
		if pointer.CanPoint(ret.Type()) {
			return false
		}
	}

	return true
}

// isConfigFiltered returns true if f should be filtered according to spec.
func isConfigFiltered(spec config.ModValSpec, f *ssa.Function) bool {
	for _, filter := range spec.Filters {
		if f != nil && filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}

	return false
}

// pureFunctions represents all the functions that do not modify external state.
//
// This assumes that the arguments' String() methods are also pure, which is the
// same assumption that the dataflow analysis makes.
var pureFunctions = map[string]struct{}{
	"print":       {},
	"println":     {},
	"fmt.Print":   {},
	"fmt.Printf":  {},
	"fmt.Println": {},
}
