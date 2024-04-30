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
	Modifications map[Entrypoint]Modifications
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

// Modifications represents the instructions that can modify an entrypoint.
type Modifications struct {
	Writes map[ssa.Instruction]struct{}
	Allocs map[ssa.Instruction]struct{}
}

// Analyze runs the analysis on lp.
func Analyze(cfg *config.Config, lp analysis.LoadedProgram, ptrRes *pointer.Result, goPtrRes *goPointer.Result) (Result, error) {
	modifications := make(map[Entrypoint]Modifications)
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
	ac := &AliasCache{
		Prog:           prog,
		PtrRes:         ptrRes,
		GoPtrRes:       goPtrRes,
		ReachableFuncs: reachable,
		ObjectPointees: make(map[ssa.Value]map[*pointer.Object]struct{}, numVals), // preallocate for speed
	}

	var errs []error
	for _, spec := range cfg.ModificationTrackingProblems {
		if err := analyze(log, spec, ac, modifications); err != nil {
			errs = append(errs, fmt.Errorf("analysis failed for spec %v: %v", spec, err))
		}
	}

	return Result{
		Modifications: modifications,
	}, errors.Join(errs...)
}

// analyze runs the analysis for a single spec and adds the write instructions to modifications.
func analyze(log *config.LogGroup, spec config.ModValSpec, c *AliasCache, modifications map[Entrypoint]Modifications) error {
	var errs []error
	entrypoints := c.findEntrypoints(spec)
	if len(entrypoints) == 0 {
		return fmt.Errorf("no entrypoints found")
	}

	for entry := range entrypoints {
		modifications[entry] = Modifications{
			Writes: make(map[ssa.Instruction]struct{}),
			Allocs: make(map[ssa.Instruction]struct{}),
		}
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

		fnsToAnalyze := c.ReachableFuncs
		log.Debugf("\tnumber of functions to analyze: %v\n", len(fnsToAnalyze))
		toAnalyze := make(map[*ssa.Function]*funcToAnalyze, len(fnsToAnalyze))
		numVals := 0
		for fn := range fnsToAnalyze {
			af := newFuncToAnalyze(fn)
			toAnalyze[fn] = af
			numVals += len(af.vals)
		}

		s := &state{
			AliasCache:       c,
			log:              log,
			spec:             spec,
			entryWrites:      make(map[ssa.Value]map[ssa.Instruction]struct{}, numVals),
			entryAllocs:      make(map[ssa.Value]map[ssa.Instruction]struct{}, numVals),
			funcsToAnalyze:   toAnalyze,
			entryPointsToSet: &intsets.Sparse{},
		}

		objs := c.Objects(val)
		// initialize points-to-set of entrypoint
		for obj := range objs {
			for _, id := range obj.NodeIDs() {
				s.entryPointsToSet.Insert(int(id))
			}
		}

		s.findModifications()

		for _, instrs := range s.entryWrites {
			for instr := range instrs {
				modifications[entry].Writes[instr] = struct{}{}
			}
		}

		for _, instrs := range s.entryAllocs {
			for instr := range instrs {
				modifications[entry].Allocs[instr] = struct{}{}
			}
		}
	}

	return errors.Join(errs...)
}

// state represents the analysis state.
// This tracks writes to a single value (entrypoint).
type state struct {
	*AliasCache
	log  *config.LogGroup
	spec config.ModValSpec

	funcsToAnalyze map[*ssa.Function]*funcToAnalyze

	// entryWrites stores the set of instructions that write to an entrypoint
	// (SSA value).
	entryWrites map[ssa.Value]map[ssa.Instruction]struct{}

	// entryAllocs stores the set of instructions that allocate memory that
	// aliases an entrypoint.
	entryAllocs map[ssa.Value]map[ssa.Instruction]struct{}

	// entryPointsToSet is the set of node ids in the objects that the
	// entrypoint points to.
	entryPointsToSet *intsets.Sparse
}

// findModifications adds all write instructions to a member of the entrypoint's
// points-to-set to s.entryWrites, and adds all instructions that allocate an
// alias of the entrypoint to s.entryAllocs.
//
// Algorithm:
//  1. For each write instruction, compute the objects that the value written to
//     can point to.
//  2. For each object, if the object is a member of the entrypoint's points-to-set,
//     then add the instruction to s.entryWrites
//  3. For each allocation instruction, compute the objects that the resulting
//     value can point to.
//  4. For each object, if the object is a member of the entrypoint's points-to-set,
//     then add the instruction to s.entryAllocs
func (s *state) findModifications() {
	log := s.log
	for _, fna := range s.funcsToAnalyze {
		for instr := range fna.writeInstrs {
			lval, ok := isWriteToScalar(instr)
			if !ok {
				continue
			}
			if s.shouldFilterValue(lval) {
				log.Tracef("lvalue %v of write instruction %v filtered by spec: skipping...", lval, instr)
				continue
			}

			mobjs := s.Objects(lval)
			for mobj := range mobjs {
				if s.entryPointsToSet.Has(int(mobj.NodeID())) {
					if _, ok := s.entryWrites[lval]; !ok {
						s.entryWrites[lval] = make(map[ssa.Instruction]struct{})
					}
					s.entryWrites[lval][instr] = struct{}{}
					break
				}
			}
		}

		for instr := range fna.allocInstrs {
			val := instr.(ssa.Value)
			if s.shouldFilterValue(val) {
				continue
			}

			mobjs := s.Objects(val)
			for mobj := range mobjs {
				if s.entryPointsToSet.Has(int(mobj.NodeID())) {
					if _, ok := s.entryAllocs[val]; !ok {
						s.entryAllocs[val] = make(map[ssa.Instruction]struct{})
					}
					s.entryAllocs[val][instr] = struct{}{}
					break
				}
			}
		}
	}
}

// shouldFilterValue returns true if the value should be filtered
// according to the spec.
func (s *state) shouldFilterValue(val ssa.Value) bool {
	return val == nil || doesConfigFilterFn(s.spec, val.Parent())
}

type funcToAnalyze struct {
	writeInstrs map[ssa.Instruction]struct{}
	allocInstrs map[ssa.Instruction]struct{}
	vals        map[ssa.Value]struct{}
}

func newFuncToAnalyze(fn *ssa.Function) *funcToAnalyze {
	vals := make(map[ssa.Value]struct{})
	addValuesOfFn(fn, vals)
	writeInstrs := make(map[ssa.Instruction]struct{})
	allocInstrs := make(map[ssa.Instruction]struct{})
	lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
		if instr == nil || instr.Parent() == nil || !instr.Pos().IsValid() {
			return
		}

		switch instr.(type) {
		case *ssa.Store, *ssa.MapUpdate, *ssa.Send:
			writeInstrs[instr] = struct{}{}
		case *ssa.Alloc, *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
			allocInstrs[instr] = struct{}{}
		}
	})

	return &funcToAnalyze{
		vals:        vals,
		writeInstrs: writeInstrs,
		allocInstrs: allocInstrs,
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

func addValuesOfFn(fn *ssa.Function, vals map[ssa.Value]struct{}) {
	lang.IterateValues(fn, func(_ int, val ssa.Value) {
		if val == nil || val.Parent() == nil {
			return
		}
		vals[val] = struct{}{}
	})
}

func isWriteToScalar(instr ssa.Instruction) (ssa.Value, bool) {
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
		panic(fmt.Errorf("invalid write instruction: %v (%T)", instr, instr))
	}

	if instr.Parent() == nil {
		return nil, false
	}
	pkg := instr.Parent().Pkg
	// we assume that errors are never used as pointer values
	if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "errors" {
		return nil, false
	}

	if !pointer.CanPoint(rval.Type()) {
		return lval, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" {
				return lval, true
			}
		}
	}

	return nil, false
}
