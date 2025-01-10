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

// Package immutability implements an analysis that disallows all modifications to a pointer-like value.
package immutability

import (
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/container/intsets"
	"golang.org/x/tools/go/ssa"
)

// ErrNoEntrypoints is the error when no entrypoints are found.
var ErrNoEntrypoints = errors.New("no entrypoints found")

// ErrEntrypointNil is the error when an entrypoint type is nil.
var ErrEntrypointNil = errors.New("entrypoint type is nil")

// ErrEntrypointNotPointer is the error when an entrypoint type is not pointer-like.
var ErrEntrypointNotPointer = errors.New("entrypoint type is not pointer-like")

// ErrEntrypointSelfReferential is the error when an entrypoint type is self-referential.
var ErrEntrypointSelfReferential = errors.New("entrypoint type is self-referential")

// AnalysisResult represents the result of the analysis.
type AnalysisResult struct {
	// Modifications represents the instructions that modify the entrypoint.
	Modifications map[Entrypoint]Modifications
}

// Entrypoint represents an Entrypoint to the analysis.
// This is an argument to a function call specified by the configuration file's
// immutability analysis spec.
type Entrypoint struct {
	// Val is the argument value.
	Val ssa.Value
	// Call is the call instruction containing the argument.
	Call ssa.CallInstruction
	// Pos is the position of the callsite, not the argument value itself.
	Pos token.Position
}

// Alloc is an instruction that allocates memory that may alias memory that an
// entrypoint points to.
type Alloc struct {
	Instr
	Value ssa.Value // Value is the value that is allocated.
}

// Modifications represents the instructions that can modify an entrypoint.
type Modifications struct {
	Writes []ptr.Write
	Reads  []ptr.Read
	Allocs []Alloc
}

// Instr is a modification instruction.
type Instr struct {
	ssa.Instruction
	Pos token.Position
}

func (i Instr) String() string {
	return fmt.Sprintf("%v in %v at %v", i.Instruction, i.Instruction.Parent(), i.Pos)
}

// Analyze runs the analysis on state.
func Analyze(state *ptr.State) (AnalysisResult, error) {
	modifications := make(map[Entrypoint]Modifications)
	prog := state.Program
	log := state.Logger
	cfg := state.Config

	reachable := state.ReachableFunctions()
	numVals := 0
	for fn := range reachable {
		lang.IterateValues(fn, func(_ int, val ssa.Value) {
			if val != nil {
				numVals++
			}
		})
	}
	log.Debugf("Found %d values in prog\n", numVals)
	if numVals == 0 {
		return AnalysisResult{}, fmt.Errorf("no values found in program: %v", prog)
	}

	ac := ptr.NewAliasCache(state)
	var errs []error
	for _, spec := range cfg.ImmutabilityProblems {
		if err := analyze(log, spec, ac, modifications); err != nil {
			errs = append(errs, fmt.Errorf("analysis failed for spec %+v: %w", spec, err))
		}
	}

	return AnalysisResult{
		Modifications: modifications,
	}, errors.Join(errs...)
}

// analyze runs the analysis for a single spec and adds the write instructions to modifications.
//
//gocyclo:ignore
func analyze(log *config.LogGroup, spec config.ImmutabilitySpec, c *ptr.AliasCache, modifications map[Entrypoint]Modifications) error {
	var errs []error
	entrypoints := findEntrypoints(c, spec)
	if len(entrypoints) == 0 {
		return ErrNoEntrypoints
	}

	for entry := range entrypoints {
		val := entry.Val
		if val.Type() == nil {
			errs = append(errs, fmt.Errorf("%w: %v type %v", ErrEntrypointNil, val, val.Type()))
			continue
		}
		if !pointer.CanPoint(val.Type()) {
			errs = append(errs, fmt.Errorf("%w: %v type %v", ErrEntrypointNotPointer, val, val.Type()))
			continue
		}

		if ptr, ok := val.Type().(*types.Pointer); ok {
			if s, ok := ptr.Elem().Underlying().(*types.Struct); ok && isSelfReferentialStruct(s) {
				errs = append(errs, fmt.Errorf("%w: %v type %v", ErrEntrypointSelfReferential, val, ptr))
				continue
			}
		}

		if doesConfigFilterFn(spec, val.Parent()) {
			log.Infof("Filtered entrypoint: %v (called in function: %v)\n", val, val.Parent())
			continue
		}

		log.Infof("Verifying immutability of: %v of %v in %v at %v\n", val, entry.Call, val.Parent(), entry.Pos)

		s := newState(c, spec, val)
		s.findModifications()

		modifications[entry] = Modifications{
			Writes: s.entryWrites,
			Reads:  s.entryReads,
			Allocs: s.entryAllocs,
		}
	}

	return errors.Join(errs...)
}

// state represents the analysis state.
// This tracks modifications of a single value (entrypoint).
type state struct {
	*ptr.AliasCache
	log  *config.LogGroup
	spec config.ImmutabilitySpec

	funcsToAnalyze map[*ssa.Function]*funcToAnalyze

	entry ssa.Value

	// entryWrites stores the set of instructions that write to memory that an
	// entrypoint (SSA value) points to.
	entryWrites []ptr.Write

	// entryReads stores the set of instructions that read from memory that an
	// entrypoint (SSA value) points to.
	entryReads []ptr.Read

	// entryAllocs stores the set of instructions that allocate memory that
	// aliases an entrypoint.
	entryAllocs []Alloc

	// entryPointsToSet is the set of node ids in the objects that the
	// entrypoint points to.
	entryPointsToSet *intsets.Sparse
}

func newState(c *ptr.AliasCache, spec config.ImmutabilitySpec, val ssa.Value) *state {
	fnsToAnalyze := c.ReachableFuncs
	c.PtrState.Logger.Debugf("\tnumber of functions to analyze: %v\n", len(fnsToAnalyze))
	toAnalyze := make(map[*ssa.Function]*funcToAnalyze, len(fnsToAnalyze))
	numVals := 0
	for fn := range fnsToAnalyze {
		af := newFuncToAnalyze(fn, c.PtrState.Program.Fset)
		toAnalyze[fn] = af
		numVals += len(af.vals)
	}

	s := &state{
		AliasCache:       c,
		log:              c.PtrState.Logger,
		spec:             spec,
		entry:            val,
		entryWrites:      make([]ptr.Write, 0, numVals),
		entryReads:       make([]ptr.Read, 0, numVals),
		entryAllocs:      make([]Alloc, 0, numVals),
		funcsToAnalyze:   toAnalyze,
		entryPointsToSet: &intsets.Sparse{},
	}

	objs := c.Objects(val)
	// initialize points-to-set of entrypoint
	for obj := range objs {
		switch data := obj.Data().(type) {
		case *ssa.MakeInterface:
			dataObjs := c.Objects(data.X) // get the objects of the concrete struct
			for obj := range dataObjs {
				for _, id := range obj.NodeIDs() {
					s.entryPointsToSet.Insert(int(id))
				}
			}
		default:
			for _, id := range obj.NodeIDs() {
				s.entryPointsToSet.Insert(int(id))
			}
		}
	}

	return s
}

// findModifications adds:
//   - all write instructions to a member of the entrypoint's
//     points-to-set to s.entryWrites
//   - all read instructions from a member of the entrypoint's points-to-set to
//     s.entryReads
//   - all instructions that allocate an alias of the entrypoint to
//     s.entryAllocs
//
// Algorithm:
//  1. For each write and read instruction, compute the objects that the value written to
//     or read from can point to.
//  2. For each object, if the object is a member of the entrypoint's points-to-set,
//     then add the instruction to s.entryWrites or s.entryReads.
//  3. For each allocation instruction, compute the objects that the resulting
//     value can point to.
//  4. For each object, if the object is a member of the entrypoint's points-to-set,
//     then add the instruction to s.entryAllocs
func (s *state) findModifications() {
	for _, fna := range s.funcsToAnalyze {
		s.findWrites(fna)
		s.findReads(fna)
		s.findAllocs(fna)
	}
}

func (s *state) findWrites(fna *funcToAnalyze) {
	for instr := range fna.writeInstrs {
		write, ok := ptr.PtrWrittenTo(instr.Instruction, instr.Pos)
		if !ok {
			continue
		}
		// We assume that errors are only used as values
		if isAllocatedErrorType(write.Target) {
			continue
		}
		if s.shouldFilterValue(write.Target) {
			s.log.Tracef("lvalue %v of write instruction %v filtered by spec: skipping...", write.Target, instr)
			continue
		}
		pos := write.Pos
		if s.PtrState.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
			s.log.Tracef("//argot:ignore write at %s", pos)
			continue
		}

		mobjs := s.Objects(write.Target)
		for mobj := range mobjs {
			if s.entryPointsToSet.Has(int(mobj.NodeID())) {
				s.entryWrites = append(s.entryWrites, write)
				break
			}
		}
	}
}

//gocyclo:ignore
func (s *state) findReads(fna *funcToAnalyze) {
	for instr := range fna.readInstrs {
		read, ok := ptr.PtrsReadFrom(instr.Instruction, instr.Pos)
		if !ok {
			continue
		}

		pos := read.Pos
		if s.PtrState.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
			s.log.Tracef("//argot:ignore read at %s", pos)
			continue
		}

		var aliasedReadVals []ssa.Value
		for _, rval := range read.Values {
			if !pointer.CanPoint(rval.Type()) {
				continue
			}
			// We assume that errors are only used as values
			if isAllocatedErrorType(rval) {
				continue
			}

			if s.shouldFilterValue(rval) {
				s.log.Tracef("rvalue %v of read instruction %v filtered by spec: skipping...", rval, instr)
				continue
			}
			if rval == s.entry {
				s.log.Tracef("rvalue %v of read instruction %v is the same as entrypoint: skipping...", rval, instr)
				continue
			}

			mobjs := s.Objects(rval)
			for mobj := range mobjs {
				if s.entryPointsToSet.Has(int(mobj.NodeID())) {
					if val, ok := mobj.Data().(ssa.Value); ok {
						// HACK Don't add reads to an object of the same type as the entrypoint
						// This is sound because we validate that an entrypoint
						// struct never has a field with the same type as it.
						typ := val.Type().Underlying()
						_, isInterface := typ.(*types.Interface)
						_, isStruct := typ.(*types.Struct)
						if isInterface || isStruct {
							if typ == s.entry.Type().Underlying() {
								s.log.Debugf("skipping read of pointer object %v (%v): has the same type as entrypoint: %v\n", mobj, val, typ)
								continue
							}
						}
					}
					aliasedReadVals = append(aliasedReadVals, rval)
					break
				}
			}
		}

		if len(aliasedReadVals) > 0 {
			s.entryReads = append(s.entryReads, ptr.Read{Instruction: read.Instruction, Values: aliasedReadVals, Pos: read.Pos})
		}
	}
}

func (s *state) findAllocs(fna *funcToAnalyze) {
	for instr := range fna.allocInstrs {
		val := instr.Instruction.(ssa.Value) // should not panic
		if s.shouldFilterValue(val) {
			s.log.Tracef("lvalue %v of alloc instruction %v filtered by spec: skipping...", val, instr)
			continue
		}
		pos := instr.Pos
		if s.PtrState.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
			s.log.Tracef("//argot:ignore alloc at %s", pos)
			continue
		}

		mobjs := s.Objects(val)
		for mobj := range mobjs {
			if s.entryPointsToSet.Has(int(mobj.NodeID())) {
				alloc := Alloc{Instr: instr, Value: val}
				s.entryAllocs = append(s.entryAllocs, alloc)
				break
			}
		}
	}
}

// shouldFilterValue returns true if the value should be filtered
// according to the spec.
func (s *state) shouldFilterValue(val ssa.Value) bool {
	return val == nil || doesConfigFilterVal(s.spec, val) || doesConfigFilterFn(s.spec, val.Parent())
}

// findEntrypoints returns all the analysis entrypoints specified by spec.
func findEntrypoints(ac *ptr.AliasCache, spec config.ImmutabilitySpec) map[Entrypoint]struct{} {
	entrypoints := make(map[Entrypoint]struct{})
	for fn, node := range ac.PtrState.PointerAnalysis.CallGraph.Nodes {
		if fn == nil {
			continue
		}
		if _, ok := ac.ReachableFuncs[fn]; !ok {
			continue
		}

		for _, inEdge := range node.In {
			if inEdge == nil || inEdge.Site == nil {
				continue
			}

			entry, ok := findEntrypoint(ac, spec, inEdge.Site.Value())
			if !ok {
				continue
			}

			entrypoints[entry] = struct{}{}
		}
	}

	return entrypoints
}

func findEntrypoint(ac *ptr.AliasCache, spec config.ImmutabilitySpec, call *ssa.Call) (Entrypoint, bool) {
	// use analysisutil entrypoint logic to take care of function aliases and
	// other edge-cases
	if !analysisutil.IsEntrypointNode(ac.PtrState.PointerAnalysis, call, spec.IsValue) {
		return Entrypoint{}, false
	}

	callPos := ac.PtrState.Program.Fset.Position(call.Pos())
	for _, cid := range spec.Values {
		// TODO parse context beforehand to prevent panics
		idx, err := strconv.Atoi(cid.Context)
		if err != nil {
			err := fmt.Errorf("cid context is not a valid argument index: %v", err)
			panic(err)
		}
		if idx < 0 {
			err := fmt.Errorf("cid context is not a valid argument index: %v < 0", idx)
			panic(err)
		}

		args := lang.GetArgs(call)
		if len(args) < idx {
			fmt.Printf("arg index: %v < want %v\n", len(args), idx)
			return Entrypoint{}, false
		}

		val := args[idx]
		if cid.Type != "" && !cid.MatchType(val.Type()) {
			continue
		}

		return Entrypoint{Val: val, Call: call, Pos: callPos}, true
	}

	return Entrypoint{}, false
}

type funcToAnalyze struct {
	writeInstrs map[Instr]struct{}
	readInstrs  map[Instr]struct{}
	allocInstrs map[Instr]struct{}
	vals        map[ssa.Value]struct{}
}

func newFuncToAnalyze(fn *ssa.Function, fset *token.FileSet) *funcToAnalyze {
	vals := make(map[ssa.Value]struct{})
	addValuesOfFn(fn, vals)
	writeInstrs := make(map[Instr]struct{})
	readInstrs := make(map[Instr]struct{})
	allocInstrs := make(map[Instr]struct{})
	lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
		if instr == nil || instr.Parent() == nil || !instr.Pos().IsValid() {
			return
		}
		pos := fset.Position(instr.Pos())

		switch instr.(type) {
		case *ssa.Store, *ssa.MapUpdate, *ssa.Send:
			writeInstrs[Instr{instr, pos}] = struct{}{}
			readInstrs[Instr{instr, pos}] = struct{}{}
		case *ssa.Alloc:
			allocInstrs[Instr{instr, pos}] = struct{}{}
		case *ssa.MakeInterface, *ssa.MakeChan, *ssa.MakeSlice:
			allocInstrs[Instr{instr, pos}] = struct{}{}
			readInstrs[Instr{instr, pos}] = struct{}{} // non-allocs are also read
		default:
			readInstrs[Instr{instr, pos}] = struct{}{}
		}
	})

	return &funcToAnalyze{
		vals:        vals,
		writeInstrs: writeInstrs,
		readInstrs:  readInstrs,
		allocInstrs: allocInstrs,
	}
}

// doesConfigFilterFn returns true if f should be filtered according to spec.
func doesConfigFilterFn(spec config.ImmutabilitySpec, f *ssa.Function) bool {
	for _, filter := range spec.Filters {
		if f != nil && filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}

	return false
}

func doesConfigFilterVal(spec config.ImmutabilitySpec, val ssa.Value) bool {
	for _, filter := range spec.Filters {
		if filter.Package != "" && filter.Type != "" {
			if filter.MatchType(val.Type()) {
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

// ReportResults writes res to a string and returns true if the analysis should fail.
func ReportResults(result AnalysisResult) (string, bool) {
	failed := false

	w := &strings.Builder{}
	w.WriteString("\nimmutability analysis results:\n")
	w.WriteString("-----------------------------\n")
	for entry, mods := range result.Modifications {
		entryVal := entry.Val
		entryPos := entry.Pos
		msg := formatutil.Green("no writes or allocations to source memory detected")
		if len(mods.Writes) > 0 || len(mods.Allocs) > 0 || len(mods.Reads) > 0 {
			msg = formatutil.Red("source memory may have been modified")
			failed = true
		}
		w.WriteString(fmt.Sprintf(
			"%s of arg %s of call %s in %s: [SSA] %s at %s\n", // safe %s (position string)
			msg,
			entry.Val.Name(),
			entry.Call.String(),
			entry.Val.Parent().String(),
			formatutil.SanitizeRepr(entryVal),
			entryPos.String(),
		))
		for _, instr := range mods.Writes {
			modInstr := instr
			modPos := modInstr.Pos
			w.WriteString(fmt.Sprintf(
				"\twrite: [SSA] %s\n\t\t%s\n\t\tto: %s\n",
				formatutil.SanitizeRepr(modInstr),
				modPos.String(), // safe %s (position string)
				modInstr.Target.String(),
			))
			failed = true
		}
		for _, instr := range mods.Reads {
			modInstr := instr
			modPos := modInstr.Pos
			from := &strings.Builder{}
			for i, v := range modInstr.Values {
				if v == nil {
					continue
				}
				from.WriteString(v.String())
				if i != len(modInstr.Values)-1 {
					from.WriteString(", ")
				}
			}
			w.WriteString(fmt.Sprintf(
				"\tread: [SSA] %s\n\t\t%s\n\t\tfrom: %v\n",
				formatutil.SanitizeRepr(modInstr),
				modPos.String(), // safe %s (position string)
				from.String(),
			))
			failed = true
		}
		for _, instr := range mods.Allocs {
			modInstr := instr
			modPos := modInstr.Pos
			w.WriteString(fmt.Sprintf(
				"\tallocation: [SSA] %s\n\t\t%s\n\t\tof: %s\n",
				formatutil.SanitizeRepr(modInstr),
				modPos.String(), // safe %s (position string)
				modInstr.Value.String(),
			))
			failed = true
		}
	}

	return w.String(), failed
}

// isSelfReferentialStruct returns true if the type of any of the fields of t
// (recursively) is equal to t.
func isSelfReferentialStruct(t *types.Struct) bool {
	allTypes := flatten(t)
	if len(allTypes) <= 1 {
		return false
	}

	// first element of allTypes is t
	for _, ft := range allTypes[1:] {
		if ft.Underlying() == t.Underlying() {
			return true
		}
	}

	return false
}

// flatten returns all the types of struct fields of t, recursively.
// No need to memoize since this is only called once per entrypoint.
func flatten(t types.Type) []types.Type {
	var res []types.Type
	switch t := t.(type) {
	case *types.Struct:
		res = append(res, t) // identity
		for i, n := 0, t.NumFields(); i < n; i++ {
			f := t.Field(i)
			for _, fi := range flatten(f.Type()) {
				res = append(res, fi)
			}
		}
	case *types.Pointer:
		// for pointers, the flattened type is the element
		res = append(res, t.Elem())
	default:
		res = append(res, t)
	}

	return res
}

func isAllocatedErrorType(val ssa.Value) bool {
	// catch cases like: change interface any <- error (err)
	if ci, ok := val.(*ssa.ChangeInterface); ok {
		val = ci.X
	}

	typ := val.Type()
	switch t := typ.(type) {
	case *types.Pointer:
		typ = t.Elem().Underlying()
	case *types.Interface:
		typ = t.Underlying()
	}

	return types.AssignableTo(typ, types.Universe.Lookup("error").Type())
}
