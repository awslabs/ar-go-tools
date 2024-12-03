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
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/container/intsets"
	"golang.org/x/tools/go/ssa"
)

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

// Write is an instruction that writes to an entrypoint's underlying memory.
type Write struct {
	Instr
	Target ssa.Value // Target is the value written to.
	Value  ssa.Value // Value is the value that is written.
}

// maxReadVals is the maximum number of values that can be read in a single instruction.
// In practice, it is rare that >maxReadVals values are ever read in a single instruction.
const maxReadVals = 11

// Read is an instruction that reads from an entrypoint's underlying memory.
type Read struct {
	Instr
	Values [maxReadVals]ssa.Value // Values are the values that are read from.
	// NOTE Values needs to be a fixed-size array so it can be used as a map key.
}

// Alloc is an instruction that allocates memory that may alias memory that an
// entrypoint points to.
type Alloc struct {
	Instr
	Value ssa.Value // Value is the value that is allocated.
}

// Modifications represents the instructions that can modify an entrypoint.
type Modifications struct {
	Writes map[Write]struct{}
	Reads  map[Read]struct{}
	Allocs map[Alloc]struct{}
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

	ac := &AliasCache{
		State:          state,
		ReachableFuncs: reachable,
		ObjectPointees: make(map[ssa.Value]map[*pointer.Object]struct{}, numVals), // preallocate for speed
	}

	var errs []error
	for _, spec := range cfg.ImmutabilityProblems {
		if err := analyze(log, spec, ac, modifications); err != nil {
			errs = append(errs, fmt.Errorf("analysis failed for spec %+v: %v", spec, err))
		}
	}

	return AnalysisResult{
		Modifications: modifications,
	}, errors.Join(errs...)
}

// analyze runs the analysis for a single spec and adds the write instructions to modifications.
//
//gocyclo:ignore
func analyze(log *config.LogGroup, spec config.ImmutabilitySpec, c *AliasCache, modifications map[Entrypoint]Modifications) error {
	var errs []error
	entrypoints := c.findEntrypoints(spec)
	if len(entrypoints) == 0 {
		return fmt.Errorf("no entrypoints found")
	}

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
		if doesConfigFilterFn(spec, val.Parent()) {
			log.Infof("Filtered entrypoint: %v (called in function: %v)\n", val, val.Parent())
			continue
		}

		modifications[entry] = Modifications{
			Writes: make(map[Write]struct{}),
			Reads:  make(map[Read]struct{}),
			Allocs: make(map[Alloc]struct{}),
		}

		log.Infof("Verifying immutability of: %v of %v in %v at %v\n", val, entry.Call, val.Parent(), entry.Pos)

		fnsToAnalyze := c.ReachableFuncs
		log.Debugf("\tnumber of functions to analyze: %v\n", len(fnsToAnalyze))
		toAnalyze := make(map[*ssa.Function]*funcToAnalyze, len(fnsToAnalyze))
		numVals := 0
		for fn := range fnsToAnalyze {
			af := newFuncToAnalyze(fn, c.State.Program.Fset)
			toAnalyze[fn] = af
			numVals += len(af.vals)
		}

		s := &state{
			AliasCache:       c,
			log:              log,
			spec:             spec,
			entryWrites:      make(map[ssa.Value]map[Write]struct{}, numVals),
			entryReads:       make(map[ssa.Value]map[Read]struct{}, numVals),
			entryAllocs:      make(map[ssa.Value]map[Alloc]struct{}, numVals),
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
			for write := range instrs {
				modifications[entry].Writes[write] = struct{}{}
			}
		}

		for readVal, instrs := range s.entryReads {
			// entrypoint value does not count as an invalid read
			if entry.Val == readVal {
				continue
			}

			for read := range instrs {
				modifications[entry].Reads[read] = struct{}{}
			}
		}

		for _, instrs := range s.entryAllocs {
			for alloc := range instrs {
				modifications[entry].Allocs[alloc] = struct{}{}
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
	spec config.ImmutabilitySpec

	funcsToAnalyze map[*ssa.Function]*funcToAnalyze

	// entryWrites stores the set of instructions that write to an entrypoint
	// (SSA value).
	entryWrites map[ssa.Value]map[Write]struct{}

	// entryReads stores the set of instructions that read from an entrypoint
	// (SSA value).
	entryReads map[ssa.Value]map[Read]struct{}

	// entryAllocs stores the set of instructions that allocate memory that
	// aliases an entrypoint.
	entryAllocs map[ssa.Value]map[Alloc]struct{}

	// entryPointsToSet is the set of node ids in the objects that the
	// entrypoint points to.
	entryPointsToSet *intsets.Sparse
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
		write, ok := ptrWrittenTo(instr)
		if !ok {
			continue
		}
		if s.shouldFilterValue(write.Target) {
			s.log.Tracef("lvalue %v of write instruction %v filtered by spec: skipping...", write.Value, instr)
			continue
		}
		pos := write.Pos
		if s.State.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
			s.log.Tracef("//argot:ignore write at %s", pos)
			continue
		}

		mobjs := s.Objects(write.Target)
		for mobj := range mobjs {
			if s.entryPointsToSet.Has(int(mobj.NodeID())) {
				if _, ok := s.entryWrites[write.Target]; !ok {
					s.entryWrites[write.Target] = make(map[Write]struct{})
				}
				s.entryWrites[write.Target][write] = struct{}{}
				break
			}
		}
	}
}

func (s *state) findReads(fna *funcToAnalyze) {
	for instr := range fna.readInstrs {
		read, ok := ptrsReadFrom(instr)
		if !ok {
			continue
		}
		pos := read.Pos
		if s.State.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
			s.log.Tracef("//argot:ignore read at %s", pos)
			continue
		}

		for _, rval := range read.Values {
			if s.shouldFilterValue(rval) {
				s.log.Tracef("rvalue %v of read instruction %v filtered by spec: skipping...", rval, instr)
				continue
			}

			mobjs := s.Objects(rval)
			for mobj := range mobjs {
				if s.entryPointsToSet.Has(int(mobj.NodeID())) {
					if _, ok := s.entryReads[rval]; !ok {
						s.entryReads[rval] = make(map[Read]struct{})
					}
					s.entryReads[rval][read] = struct{}{}
					break
				}
			}
		}
	}
}

func (s *state) findAllocs(fna *funcToAnalyze) {
	for instr := range fna.allocInstrs {
		val := instr.Instruction.(ssa.Value)
		if s.shouldFilterValue(val) {
			s.log.Tracef("lvalue %v of alloc instruction %v filtered by spec: skipping...", val, instr)
			continue
		}
		pos := instr.Pos
		if s.State.Annotations.IsIgnoredPos(pos, s.spec.Tag) {
			s.log.Tracef("//argot:ignore alloc at %s", pos)
			continue
		}

		mobjs := s.Objects(val)
		for mobj := range mobjs {
			if s.entryPointsToSet.Has(int(mobj.NodeID())) {
				if _, ok := s.entryAllocs[val]; !ok {
					s.entryAllocs[val] = make(map[Alloc]struct{})
				}
				s.entryAllocs[val][Alloc{Instr: instr, Value: val}] = struct{}{}
				break
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

func addValuesOfFn(fn *ssa.Function, vals map[ssa.Value]struct{}) {
	lang.IterateValues(fn, func(_ int, val ssa.Value) {
		if val == nil || val.Parent() == nil {
			return
		}
		vals[val] = struct{}{}
	})
}

func ptrWrittenTo(instruction Instr) (Write, bool) {
	var lval ssa.Value
	var rval ssa.Value
	instr := instruction.Instruction
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
		return Write{}, false
	}
	pkg := instr.Parent().Pkg
	// we assume that errors are never used as pointer values
	if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "errors" {
		return Write{}, false
	}

	if !pointer.CanPoint(rval.Type()) {
		return Write{Instr: instruction, Target: lval, Value: rval}, true
	}

	// calls to append builtin function modify
	if call, ok := rval.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
			if builtin.Object().Name() == "append" {
				return Write{Instr: instruction, Target: lval, Value: rval}, true
			}
		}
	}

	return Write{}, false
}

//gocyclo:ignore
func ptrsReadFrom(instruction Instr) (Read, bool) {
	var rvals [maxReadVals]ssa.Value
	add := func(vs ...ssa.Value) {
		i := 0
		for _, v := range vs {
			if v == nil {
				continue
			}

			if i == maxReadVals {
				panic(fmt.Errorf("too many values read in instr %v: %v", instruction, rvals))
			}

			if pointer.CanPoint(v.Type()) {
				rvals[i] = v
				i++
			}
		}
	}

	instr := instruction.Instruction
	switch instr := instr.(type) {
	case *ssa.BinOp:
		add(instr.X, instr.Y)
	case *ssa.Call:
		add(instr.Call.Args...)
	case *ssa.ChangeInterface:
		add(instr.X)
	case *ssa.ChangeType:
		add(instr.X)
	case *ssa.Convert:
		add(instr.X)
	case *ssa.Extract:
		add(instr.Tuple)
	case *ssa.Field:
		add(instr.X)
	case *ssa.FieldAddr:
		add(instr.X)
	case *ssa.Go:
		add(instr.Call.Args...)
	case *ssa.If:
		add(instr.Cond)
	case *ssa.Index:
		add(instr.X, instr.Index)
	case *ssa.IndexAddr:
		add(instr.X, instr.Index)
	case *ssa.Lookup:
		add(instr.X, instr.Index)
	case *ssa.MakeChan:
		add(instr.Size)
	case *ssa.MakeClosure:
		add(instr.Bindings...)
	case *ssa.MakeInterface:
		add(instr.X)
	case *ssa.MakeMap:
		add(instr.Reserve)
	case *ssa.MakeSlice:
		add(instr.Len, instr.Cap)
	case *ssa.MapUpdate:
		add(instr.Map, instr.Key, instr.Value)
	case *ssa.MultiConvert:
		add(instr.X)
	case *ssa.Next:
		add(instr.Iter)
	case *ssa.Panic:
		add(instr.X)
	case *ssa.Phi:
		add(instr.Edges...)
	case *ssa.Return:
		add(instr.Results...)
	case *ssa.Select:
		for _, state := range instr.States {
			add(state.Chan, state.Send)
		}
	case *ssa.Send:
		add(instr.Chan, instr.X)
	case *ssa.Slice:
		add(instr.X, instr.Low, instr.High, instr.Max)
	case *ssa.SliceToArrayPointer:
		add(instr.X)
	case *ssa.Store:
		add(instr.Addr, instr.Val)
	case *ssa.TypeAssert:
		add(instr.X)
	case *ssa.UnOp:
		add(instr.X)
	}

	if len(rvals) == 0 {
		return Read{Instr: instruction, Values: [maxReadVals]ssa.Value{}}, false
	}

	return Read{Instr: instruction, Values: [maxReadVals]ssa.Value(rvals)}, true
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
		for instr := range mods.Writes {
			modInstr := instr
			modPos := modInstr.Pos
			w.WriteString(fmt.Sprintf(
				"\twrite: [SSA] %s in function %s\n\t\t%s\n\t\tto: %s\n",
				formatutil.SanitizeRepr(modInstr),
				modInstr.Parent().String(),
				modPos.String(), // safe %s (position string)
				modInstr.Target.String(),
			))
			failed = true
		}
		for instr := range mods.Reads {
			modInstr := instr
			modPos := modInstr.Pos
			from := &strings.Builder{}
			for _, v := range modInstr.Values {
				if v == nil {
					continue
				}
				from.WriteString(v.String())
			}
			w.WriteString(fmt.Sprintf(
				"\tread: [SSA] %s in function %s\n\t\t%s\n\t\tfrom: %v\n",
				formatutil.SanitizeRepr(modInstr),
				modInstr.Parent().String(),
				modPos.String(), // safe %s (position string)
				from.String(),
			))
			failed = true
		}
		for instr := range mods.Allocs {
			modInstr := instr
			modPos := modInstr.Pos
			w.WriteString(fmt.Sprintf(
				"\tallocation: [SSA] %s in function %s\n\t\t%s\n\t\tof: %s\n",
				formatutil.SanitizeRepr(modInstr),
				modInstr.Parent().String(),
				modPos.String(), // safe %s (position string)
				modInstr.Value.String(),
			))
			failed = true
		}
	}

	return w.String(), failed
}
