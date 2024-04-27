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

	reachable := lang.CallGraphReachable(ptrRes.CallGraph, false, false)
	numVals := 0
	for fn := range reachable {
		lang.IterateValues(fn, func(_ int, val ssa.Value) {
			if val != nil {
				numVals++
			}
		})
	}
	ac := &aliasCache{
		prog:           prog,
		ptrRes:         ptrRes,
		goPtrRes:       goPtrRes,
		reachableFuncs: reachable,
		objectPointees: make(map[ssa.Value]map[*pointer.Object]struct{}, numVals), // preallocate for speed
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

		objs := c.objects(val)
		// initialize points-to-set of entrypoint
		for obj := range objs {
			for _, id := range obj.NodeIDs() {
				s.entryPointsToSet.Insert(int(id))
			}
		}

		s.findWritesToAliases()
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

// findWritesToAliases adds all write instructions to a member of the entrypoint's
// points-to-set to s.writesToAlias.
//
// Algorithm:
//  1. For each write instruction (including alloc), compute the objects that
//     the value can point to.
//  2. For each object, if the object is a member of the entrypoint's points-to-set,
//     then add the instruction to s.writesToAlias
func (s *state) findWritesToAliases() {
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
				panic(fmt.Errorf("invalid write instruction: %v (%T)", instr, instr))
			}
			if s.shouldFilterValue(mval) {
				continue
			}

			mobjs := s.objects(mval)
			for mobj := range mobjs {
				if s.entryPointsToSet.Has(int(mobj.NodeID())) {
					if _, ok := s.writesToAlias[mval]; !ok {
						s.writesToAlias[mval] = make(map[ssa.Instruction]struct{})
					}
					s.writesToAlias[mval][instr] = struct{}{}
					break
				}
			}
		}
	}
}

// objects returns all the unique objects that val points to.
func (ac *aliasCache) objects(val ssa.Value) map[*pointer.Object]struct{} {
	if mi, ok := val.(*ssa.MakeInterface); ok {
		// if val is an interface, the object is the concrete struct
		val = mi.X
	}
	if res, ok := ac.objectPointees[val]; ok && len(res) > 0 {
		return res
	}

	res := make(map[*pointer.Object]struct{})
	ptrs := findAllPointers(ac.ptrRes, val)
	for _, ptr := range ptrs {
		for _, label := range ptr.PointsTo().Labels() {
			obj := label.Obj()
			if obj == nil {
				continue
			}
			res[obj] = struct{}{}
		}
	}

	ac.objectPointees[val] = res
	return res
}

// shouldFilterValue returns true if the value should be filtered
// according to the spec.
func (s *state) shouldFilterValue(val ssa.Value) bool {
	return val == nil || doesConfigFilterFn(s.spec, val.Parent())
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
