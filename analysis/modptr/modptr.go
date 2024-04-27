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
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/container/intsets"
	goPointer "golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// Result represents the result of the analysis.
type Result struct {
	// Modifications represents the instructions that modify the entrypoint.
	Modifications map[Entrypoint]map[ssa.Instruction]struct{}
}

// Entrypoint represents an Entrypoint to the analysis.
// This is an argument to a function call specified by the configuration file's
// modval analysis spec.
type Entrypoint struct {
	// Val is the argument value.
	Val ssa.Value
	// Call is the call instruction containing the argument.
	Call ssa.CallInstruction
	// Pos is the position of the callsite, not the argument value itself.
	Pos token.Position
}

// Analyze runs the analysis on lp.
func Analyze(cfg *config.Config, lp analysis.LoadedProgram, ptrRes *pointer.Result, goPtrRes *goPointer.Result) (Result, error) {
	modifications := map[Entrypoint]map[ssa.Instruction]struct{}{}
	prog := lp.Program
	log := config.NewLogGroup(cfg)

	// pre-allocate maps for speed
	numPtrs := len(ptrRes.Queries) + len(ptrRes.IndirectQueries)
	reachable := lang.CallGraphReachable(ptrRes.CallGraph, false, false)
	ac := &aliasCache{
		prog:                         prog,
		ptrRes:                       ptrRes,
		goPtrRes:                     goPtrRes,
		reachableFuncs:               reachable,
		globalPtrsTo:                 make(map[ssa.Value][]pointer.Pointer),
		globalValsThatAlias:          make(map[pointer.Pointer]map[ssa.Value]struct{}, numPtrs),
		computedAliasedValuesForFunc: make(map[pointer.Pointer]map[*ssa.Function]struct{}),
		computedTransitiveAliases:    make(map[ssa.Value]struct{}),
	}
	progTypes := prog.RuntimeTypes()
	tc := &typeCache{
		progTypes:  progTypes,
		implements: make(map[*types.Interface][]types.Type),
		basic:      make(map[types.Type][]*types.Basic),
	}
	c := &cache{
		aliasCache: ac,
		typeCache:  tc,
	}

	var errs []error
	for _, spec := range cfg.ModificationTrackingProblems {
		if err := analyze(log, spec, c, modifications); err != nil {
			errs = append(errs, fmt.Errorf("analysis failed for spec %v: %v", spec, err))
		}
	}

	return Result{
		Modifications: modifications,
	}, errors.Join(errs...)
}

// analyze runs the analysis for a single spec and adds the write instructions to modifications.
func analyze(log *config.LogGroup, spec config.ModValSpec, c *cache, modifications map[Entrypoint]map[ssa.Instruction]struct{}) error {
	var errs []error
	entrypoints := c.findEntrypoints(spec)
	for entry := range entrypoints {
		val := entry.Val
		if val.Type() == nil {
			errs = append(errs, fmt.Errorf("entrypoint %v type is nil: %T\n", val, val))
			continue
		}
		if !pointer.CanPoint(val.Type()) {
			errs = append(errs, fmt.Errorf("entrypoint is a non-pointer type: %v", val.Type()))
			continue
		}
		log.Infof("ENTRY: %v of %v in %v at %v\n", val.Name(), entry.Call, val.Parent(), entry.Pos)

		// Only analyze the functions can modify the entrypoint.
		//
		// Crucially, "reachable" functions do not exclude functions that are
		// filtered by the config. This is because filtered functions may
		// produce intermediate pointers that may alias pointers used in
		// unfiltered functions.
		entryTypes := c.typeCache.allBasicTypes(val.Type())
		log.Debugf("\tentrypoint types: %v\n", entryTypes)
		fnsToAnalyze := make(map[*ssa.Function]bool)
		fnsToAnalyze[val.Parent()] = true // always analyze the entrypoint function
		for fn := range c.reachableFuncs {
			if !isFnPure(c.typeCache, entryTypes, fn) {
				fnsToAnalyze[fn] = true
			}
		}
		log.Debugf("\tnumber of functions to analyze: %v\n", len(fnsToAnalyze))
		toAnalyze := make(map[*ssa.Function]*funcToAnalyze, len(fnsToAnalyze))
		numVals := 0
		numInstrs := 0
		for fn := range fnsToAnalyze {
			af := newFuncToAnalyze(c.typeCache, entryTypes, fn)
			toAnalyze[fn] = af
			numVals += len(af.vals)
			numInstrs += len(af.instrs)
		}
		log.Debugf("\tnumber of vals to analyze: %v\n", numVals)
		log.Debugf("\tnumber of write instructions to analyze: %v\n", numInstrs)

		s := &state{
			cache:            c,
			log:              log,
			spec:             spec,
			writesToAlias:    make(map[ssa.Value]map[ssa.Instruction]struct{}),
			funcsToAnalyze:   toAnalyze,
			entryPointsToSet: &intsets.Sparse{},
		}

		// report functions with a high number of SSA values for debugging purposes
		if log.LogsDebug() {
			fns := mostExpensiveFns(c.typeCache, entryTypes, fnsToAnalyze)
			if len(fns) > 0 {
				log.Debugf("\tmost expensive functions (name | signature | number of values):\n")
				for _, ef := range fns {
					log.Debugf("\t\t%v | %v | %v\n", ef.fn.String(), ef.fn.Signature, ef.numVals)
				}
			}
		}

		objs := objects(s.ptrRes, val)
		// initialize points-to-set of entrypoint
		fmt.Println("initializing entry points-to set")
		for _, obj := range objs {
			fmt.Printf("\tobject: %v\n", obj)
			for _, id := range obj.NodeIDs() {
				fmt.Printf("\t\tid: %v\n", id)
				s.entryPointsToSet.Insert(int(id))
			}
		}

		s.findWritesToAliases(objs)
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
	*cache
	log  *config.LogGroup
	spec config.ModValSpec

	funcsToAnalyze map[*ssa.Function]*funcToAnalyze
	// writesToAlias stores the set of instructions that write to an alias
	// (SSA value).
	writesToAlias map[ssa.Value]map[ssa.Instruction]struct{}
	// entryPointsToSet is the set of node ids in the objects that the
	// entrypoint points to.
	entryPointsToSet *intsets.Sparse
}

// cache represents a "global" cache for the analysis.
type cache struct {
	*aliasCache
	*typeCache
}

// findWritesToAliases adds all write instructions to transitive aliases of
// ptrs to s.writesToAlias.
//
// Algorithm:
//  1. Compute all values reachable from the entrypoint that transitively
//     may-alias ptrs. This initializes the global may-alias cache.
//  2. Filter all may-aliased values that do not need to be considered as
//     aliases of the entrypoint because of the configuraton spec.
//  3. For every instruction reachable from the entrypoint, if the lvalue is an
//     alias, or the instruction allocates a value to an alias, then the alias
//     has been "modified".
func (s *state) findWritesToAliases(objs []*pointer.Object) {
	//log := s.log
	for _, fna := range s.funcsToAnalyze {
		for instr := range fna.instrs {
			// mX is short for modifiedX
			var mval ssa.Value
			switch instr := instr.(type) {
			case *ssa.Alloc:
				mval = instr
			case *ssa.Store:
				mval = instr.Addr
			case *ssa.MapUpdate:
				mval = instr.Map
			case *ssa.Send:
				mval = instr.Chan
			default:
				panic("invalid write instruction")
			}

			mobjs := objects(s.ptrRes, mval)
			for _, mobj := range mobjs {
				if s.entryPointsToSet.Has(int(mobj.NodeID())) {
					if _, ok := s.writesToAlias[mval]; !ok {
						s.writesToAlias[mval] = make(map[ssa.Instruction]struct{})
					}
					s.writesToAlias[mval][instr] = struct{}{}
				}
			}
		}
	}
}

// Idea:
// Find all (single?) objects that the entrypoint value points to
// For every write instruction, if the value written to is a node in an entrypoint object, then it can modify the entrypoint

// objects returns all the unique objects that val points to.
func objects(ptrRes *pointer.Result, val ssa.Value) []*pointer.Object {
	if mi, ok := val.(*ssa.MakeInterface); ok {
		// if val is an interface, the object is the concrete struct
		val = mi.X
	}

	var res []*pointer.Object
	seen := make(map[*pointer.Object]struct{})
	ptrs := findAllPointers(ptrRes, val)
	for _, ptr := range ptrs {
		for _, label := range ptr.PointsTo().Labels() {
			obj := label.Obj()
			if obj == nil {
				continue
			}
			if _, ok := seen[obj]; ok {
				continue
			}

			res = append(res, obj)
			seen[obj] = struct{}{}
		}
	}

	return res
}

// shouldFilterValue returns true if the value should be filtered
// according to the spec.
func (s *state) shouldFilterValue(val ssa.Value) bool {
	return val == nil || doesConfigFilterFn(s.spec, val.Parent())
}

func (s *state) transitivePointersTo(val ssa.Value) []pointer.Pointer {
	if ptrs, ok := s.aliasCache.globalPtrsTo[val]; ok {
		return ptrs
	}

	stack := findAllPointers(s.aliasCache.ptrRes, val)
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

			labelPtrs := findAllPointers(s.aliasCache.ptrRes, val)
			//stack = append(stack, labelPtrs...)
			for _, ptr := range labelPtrs {
				ptrs = append(ptrs, ptr)
			}
		}
	}

	s.aliasCache.globalPtrsTo[val] = ptrs
	return ptrs
}

// allAliasesOf computes all the values that are in the points-to set of a
// pointer that transitively may-alias ptr.
// This function only analyzes the values reachable from a single analysis
// entrypoint.
func (s *state) allAliasesOf(ptr pointer.Pointer) map[ssa.Value]struct{} {
	// Even if the aliases of ptr are cached, the cache may have missed some,
	// therefore the rest need to be analyzed.
	// This is a global cache so some aliased values may not be reachable from the entrypoint
	// and therefore those values do not need to be analyzed.
	cachedAliases, hasCachedAliases := s.aliasCache.globalValsThatAlias[ptr]
	aliases := make(map[ssa.Value]struct{}, len(cachedAliases))
	if hasCachedAliases && len(cachedAliases) > 0 {
		for v := range cachedAliases {
			if _, ok := s.funcsToAnalyze[v.Parent()]; !ok {
				continue
			}

			aliases[v] = struct{}{}
		}
	}

	for fn, rfn := range s.funcsToAnalyze {
		if _, ok := s.computedAliasedValuesForFunc[ptr][fn]; ok {
			// skip if we already analyzed the function's aliased values
			continue
		}

		for val := range rfn.vals {
			if _, ok := aliases[val]; ok {
				continue
			}

			ptrs := s.transitivePointersTo(val)
			for _, valPtr := range ptrs {
				if valPtr.MayAlias(ptr) {
					aliases[val] = struct{}{}
					break
				}
			}
		}

		if _, ok := s.computedAliasedValuesForFunc[ptr]; !ok {
			s.computedAliasedValuesForFunc[ptr] = make(map[*ssa.Function]struct{})
		}
		s.computedAliasedValuesForFunc[ptr][fn] = struct{}{}
	}

	// update the global cache with the newly-computed aliases
	if !hasCachedAliases {
		s.aliasCache.globalValsThatAlias[ptr] = make(map[ssa.Value]struct{}, len(aliases))
	}
	for val := range aliases {
		s.aliasCache.globalValsThatAlias[ptr][val] = struct{}{}
	}

	return aliases
}

type funcToAnalyze struct {
	instrs map[ssa.Instruction]struct{}
	vals   map[ssa.Value]struct{}
}

func newFuncToAnalyze(tc *typeCache, entryTypes []*types.Basic, fn *ssa.Function) *funcToAnalyze {
	vals := make(map[ssa.Value]struct{})
	addValuesOfFn(tc, entryTypes, fn, vals)
	instrs := make(map[ssa.Instruction]struct{})
	lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
		if instr == nil || instr.Parent() == nil {
			return
		}

		switch instr.(type) {
		case *ssa.Alloc, *ssa.Store, *ssa.MapUpdate, *ssa.Send:
			instrs[instr] = struct{}{}
		}
	})

	return &funcToAnalyze{
		vals:   vals,
		instrs: instrs,
	}
}

// doesConfigFilterFn returns true if f should be filtered according to spec.
func doesConfigFilterFn(spec config.ModValSpec, f *ssa.Function) bool {
	for _, filter := range spec.Filters {
		if f != nil && filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}

	return false
}
