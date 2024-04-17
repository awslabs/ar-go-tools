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
	"runtime"
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
	// Pos is the position of the callsite, not the argument value itself.
	Pos token.Position
}

// Analyze runs the analysis on prog.
func Analyze(cfg *config.Config, lp analysis.LoadedProgram, ptrRes *pointer.Result) (Result, error) {
	modifications := map[Entrypoint]map[ssa.Instruction]struct{}{}
	prog := lp.Program
	log := config.NewLogGroup(cfg)

	goroot := runtime.GOROOT()
	// reachable := ssautil.AllFunctions(prog)
	_ = ssautil.AllFunctions
	_ = goroot
	reachable := lang.CallGraphReachable(ptrRes.CallGraph, false, false)

	// Skip analyzing any function in the dependencies or standard library that
	// cannot modify external state
	// for f := range reachable {
	// 	if f == nil || isDefaultFiltered(prog, goroot, f) {
	// 		delete(reachable, f)
	// 	}
	// }
	allInstrs := allInstructions(reachable)
	allVals := allValues(reachable)
	pv := progVals{
		prog:           prog,
		ptrRes:         ptrRes,
		allInstrs:      allInstrs,
		allValues:      allVals,
		reachableFuncs: reachable,
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

// progVals contains all the usable SSA instructions/values in the program used
// for the analysis.
type progVals struct {
	prog           *ssa.Program
	ptrRes         *pointer.Result
	allInstrs      map[ssa.Instruction]struct{}
	allValues      map[ssa.Value]struct{}
	reachableFuncs map[*ssa.Function]bool
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
		res := isConfigFiltered(spec, fn)
		if res {
			log.Infof("FILTERED: %v\n", fn)
		}
		return res
	}

	var errs []error
	entrypoints := findEntrypoints(prog, reachable, spec, ptrRes)
	for entry := range entrypoints {
		val := entry.Val
		if !pointer.CanPoint(val.Type()) {
			errs = append(errs, fmt.Errorf("invalid entrypoint type: %v", val.Type()))
			continue
		}
		parent := val.Parent()
		reachableFns := lang.ReachableFrom(ptrRes.CallGraph, parent, filterFn)
		// prune search space by filtering functions that do not need to be
		// analyzed
		for fn := range reachableFns {
			if fn == parent {
				continue
			}

			if cannotModify(fn) {
				log.Infof("FILTERED: %v\n", fn)
				delete(reachableFns, fn)
			}
		}
		for fn := range reachableFns {
			log.Infof("REACHABLE: %v\n", fn)
		}
		reachableVals := allValues(reachableFns)

		log.Infof("ENTRY: %v in %v at %v\n", val, val.Parent(), entry.Pos)
		log.Infof("\tnumber of reachable vals: %v\n", len(reachableVals))
		s := &state{
			progVals:      pv,
			log:           log,
			spec:          spec,
			writesToAlias: make(map[ssa.Value]map[ssa.Instruction]struct{}),
			filterValue:   shouldFilter,
			reachableVals: reachableVals,
		}
		aliases := make(map[pointer.Pointer]struct{})
		lang.FindTransitivePointers(ptrRes, val, aliases)
		s.findWritesToAliases(aliases)
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

	reachableInstrs map[ssa.Instruction]struct{}
	reachableVals   map[ssa.Value]struct{}
	// filterValue returns true if the value should be filtered
	// according to the spec.
	filterValue func(config.ModValSpec, ssa.Value) bool
	// writesToAlias stores the set of instructions that write to an alias
	// (SSA value).
	writesToAlias map[ssa.Value]map[ssa.Instruction]struct{}
}

// findWritesToAliases adds all write instructions to transitive aliases of aliases to s.writesToAlias.
func (s *state) findWritesToAliases(aliases map[pointer.Pointer]struct{}) {
	log := s.log
	for ptr := range aliases {
		allAliases := make(map[ssa.Value]struct{})
		lang.FindAllMayAliases(s.ptrRes, s.allValues, ptr, allAliases)
		for alias := range allAliases {
			if _, ok := s.reachableVals[alias]; !ok {
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
			log.Tracef("Alias %v: %v in %v\n", alias.Name(), alias, alias.Parent())
			if _, ok := s.writesToAlias[alias]; !ok {
				s.writesToAlias[alias] = make(map[ssa.Instruction]struct{})
			}

			for instr := range s.allInstrs {
				allocs := false
				if alloc, ok := instr.(*ssa.Alloc); ok {
					allocs = alloc == alias
				}

				if _, ok := lang.InstrWritesToVal(instr, alias); ok || allocs {
					log.Tracef("Instr %v writes to alias %v\n", instr, alias)
					s.writesToAlias[alias][instr] = struct{}{}
				}
			}
		}
	}
}

// addTransitiveMayAliases adds all transitive aliases of alias to allAliases.
func (s *state) addTransitiveMayAliases(alias ssa.Value, allAliases map[ssa.Value]struct{}) {
	visit := make(map[pointer.Pointer]struct{})
	lang.FindTransitivePointers(s.ptrRes, alias, visit)
	seen := make(map[pointer.Pointer]struct{})
	for len(visit) > 0 {
		var cur pointer.Pointer
		for v := range visit {
			// pick any value from the map
			cur = v
			break
		}
		delete(visit, cur)
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		newAliases := make(map[ssa.Value]struct{})
		lang.FindAllMayAliases(s.ptrRes, s.allValues, cur, newAliases)
		for a := range newAliases {
			if _, ok := allAliases[a]; ok || s.filterValue(s.spec, a) {
				continue
			}
			if _, ok := s.reachableVals[a]; !ok {
				continue
			}

			allAliases[a] = struct{}{}
			s.log.Tracef("found transitive alias of %v: %v (%v) in %v\n", alias, a, a.Name(), a.Parent())
			lang.FindTransitivePointers(s.ptrRes, a, visit)
		}
	}
}

func allInstructions(fns map[*ssa.Function]bool) map[ssa.Instruction]struct{} {
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
		return Entrypoint{Val: val, Pos: callPos}, true
	}

	return Entrypoint{}, false
}

// cannotModify returns true if no instruction in the body of the function can
// modify a value outside the function body, or the function does not return a
// pointer.
//
// We assume that the analysis is not tracking modifications to a global value.
func cannotModify(f *ssa.Function) bool {
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
