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

// Package structinit implements the struct initialization syntactic analysis.
package structinit

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// AnalysisReqs groups the options of the analysis together
type AnalysisReqs struct {
	// Tag is the tag of the problem to analyze
	Tag string
}

// AnalysisResult is the result of the struct-init analysis.
type AnalysisResult struct {
	// InitInfos is a mapping from the named struct type to its initialization
	// information.
	InitInfos map[*types.Named]InitInfo
}

// InitInfo is the initialization information for a struct.
type InitInfo struct {
	// Tag is the tag of the problem this initinfo corresponds to
	Tag string
	// ZeroAllocs is a list of the zero-value allocations of the struct.
	ZeroAllocs []ZeroAlloc
	// InvalidWrites is a mapping of the struct field to all the invalid writes
	// to that field.
	InvalidWrites map[*types.Var][]InvalidWrite
	// BadReinits is a list of bad reinitializations
	BadReinits []BadReinit
}

// ZeroAlloc is an empty (zero) allocation of a struct.
type ZeroAlloc struct {
	// Alloc is the allocation instruction.
	Alloc ssa.Instruction
	// Pos is the position of the instruction.
	Pos token.Position
}

// InvalidWrite is a write to a field of the struct of value Got that is not the
// configured value (Want).
type InvalidWrite struct {
	// Got is the value actually written.
	Got ssa.Value
	// Want is the configured value that should have been written.
	Want ssa.Value
	// Instr is the instruction performing the write.
	Instr ssa.Instruction
	// Pos is the position of the instruction.
	Pos token.Position
}

// BadReinit is a function call resulting in a struct that should have specific
// fields reinitialized, but it hasn't.
type BadReinit struct {
	// Call is the function call instruction.
	Call ssa.Instruction
	// Pos is the position of the instruction.
	Pos token.Position
}

// Analyze runs the analysis on prog.
func Analyze(state *ptr.State, reqs AnalysisReqs) (AnalysisResult, error) {
	specs := structInitSpecs(state.Config, state.Target, reqs.Tag)
	state.Logger.Infof("%d struct-init specs to check: %s", len(specs), strings.Join(
		funcutil.Map(specs, func(ss config.StructInitSpec) string { return ss.Tag }), ","))
	if len(specs) == 0 {
		// If there is no specs here, it's like because of the tags being filtered out by structInitSpecs
		state.Logger.Infof("No struct-init specs matching configuration; check the tags if you expected a result")
		return AnalysisResult{}, nil
	}
	res := AnalysisResult{InitInfos: make(map[*types.Named]InitInfo)}
	for _, spec := range specs {
		if err := runSpec(state, reqs, spec, res); err != nil {
			return res, fmt.Errorf("failed to run analysis for spec tag %s: %v", spec.Tag, err)
		}
	}

	return res, nil
}

func runSpec(st *ptr.State, reqs AnalysisReqs, spec config.StructInitSpec, res AnalysisResult) error {
	s, err := newState(spec, st)
	if err != nil {
		return fmt.Errorf("failed to initialize analysis: %v", err)
	}

	runZeroAllocAnalysis(s, res)

	// Run the must-reinit checks
	for sType, findings := range runMustReinitChecks(s) {
		if iInfo, ok := res.InitInfos[sType]; ok {
			iInfo.BadReinits = findings
			res.InitInfos[sType] = iInfo
		} else {
			res.InitInfos[sType] = InitInfo{Tag: reqs.Tag, BadReinits: findings}
		}
	}

	runInvalidWritesAnalysis(s, res)

	return nil
}

// state keeps track of the state of the analysis for a given spec.
type state struct {
	// spec is the spec being analyzed currently.
	spec config.StructInitSpec
	// allocs are all the values of the struct to track that were allocated in the program.
	allocs []alloced
	// types are all the possible underlying types the struct could have.
	// This is represented as a map from the underlying type to the named type.
	types map[*types.Struct]*types.Named
	// fieldExpectedValue is a mapping of the struct field to the concrete value it
	// should be initialized to according to the spec.
	//
	// For now, the value can only be:
	// - *ssa.NamedConst
	// - *ssa.Function
	fieldExpectedValue map[*types.Var]ssa.Value

	fns      map[*ssa.Function]bool
	ptrState *ptr.State
}

// newState initializes a new analysis state to analyze all structs in the program that match the
// struct specified in the spec.
func newState(spec config.StructInitSpec, st *ptr.State) (*state, error) {
	fns := st.ReachableFunctions()
	var allocs []alloced
	structToNamed := make(map[*types.Struct]*types.Named)
	for fn := range fns {
		if isFiltered(spec, fn) {
			st.Logger.Debugf("Skipping analyzing structs allocated in function: %v\n", fn)
			delete(fns, fn)
		}

		as := findAllocsInFn(spec, structToNamed, fn)
		allocs = append(allocs, as...)
	}

	if len(structToNamed) == 0 {
		return nil, fmt.Errorf("no struct types found in the program for spec: %+v", spec)
	}
	var structTyp *types.Struct
	for t := range structToNamed {
		// doesn't really matter which type to choose because the field names should all be the same
		structTyp = t
	}
	var fieldVal map[*types.Var]ssa.Value
	if len(spec.FieldsSet) > 0 {
		// only allocate the map when necessary
		fieldVal = make(map[*types.Var]ssa.Value)
	}
	for _, fieldSpec := range spec.FieldsSet {
		var field *types.Var
		for i := 0; i < structTyp.NumFields(); i++ {
			f := structTyp.Field(i)
			if fieldSpec.Field == "" {
				return nil, fmt.Errorf("field name in fields-set spec should not be empty: %+v", fieldSpec)
			}
			if fieldSpec.Field == f.Name() {
				field = f
				break
			}
		}

		if field == nil {
			return nil, fmt.Errorf("failed to find field %v in struct %v from spec: %+v", fieldSpec.Field, structTyp, spec)
		}
		if fieldSpec.Value.Const != "" {
			c, ok := findNamedConst(st.Program, fieldSpec.Value)
			if !ok {
				return nil, fmt.Errorf("failed to find a named constant in the program for %v in spec: %+v", fieldSpec.Value, spec)
			}

			fieldVal[field] = c.Value
		}

		if fieldSpec.Value.Method != "" {
			f, ok := findMethod(st.Program, fieldSpec.Value)
			if !ok {
				return nil, fmt.Errorf("failed to find a function in the program for %v in spec: %+v", fieldSpec.Value, spec)
			}

			fieldVal[field] = f
		}
	}

	return &state{
		spec:               spec,
		allocs:             allocs,
		types:              structToNamed,
		fieldExpectedValue: fieldVal,
		ptrState:           st,
		fns:                fns,
	}, nil
}

// findAllocsInFn returns all the values of the struct to track according to spec that were
// allocated in fn.
//
// Updates structToNamed with the named type for the underlying struct type.
// An allocated value may come from a ChangeType instruction involving two distinct types, hence the
// need for a map.
func findAllocsInFn(spec config.StructInitSpec, structToNamed map[*types.Struct]*types.Named, fn *ssa.Function) []alloced {
	var allocs []alloced

	lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
		if !instrCanAlloc(instr) {
			return
		}

		structAllocs := allocsInInstr(spec, instr, structToNamed)
		allocs = append(allocs, structAllocs...)
	})

	return allocs
}

func runInvalidWritesAnalysis(st *state, res AnalysisResult) {
	program := st.ptrState.Program
	logger := st.ptrState.Logger
	for fn := range st.fns {
		lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
			if instr == nil || instr.Parent() == nil || !instr.Pos().IsValid() {
				return
			}
			if summaries.IsStdPackageName(lang.PackageNameFromFunction(instr.Parent())) {
				return
			}

			if storeInstr, ok := instr.(*ssa.Store); ok {
				pos := program.Fset.Position(storeInstr.Pos())
				if write, ok := isInvalidWrite(st, storeInstr, pos); ok {
					namedType := write.structType.named
					is := res.InitInfos[namedType]
					if st.ptrState.Annotations.IsIgnoredPos(pos, is.Tag) {
						logger.Infof("annotation found, ignored %s: invalid write to struct field %v.%s at %s\n",
							is.Tag, namedType, write.fieldType.Name(), pos)
					} else {
						logger.Warnf("%s: found invalid write of value %v (wanted %v) to struct field %v.%v at %v\n",
							is.Tag, write.write.Got, write.write.Want, namedType, write.fieldType.Name(), pos)
						if is.InvalidWrites == nil {
							is.InvalidWrites = make(map[*types.Var][]InvalidWrite)
						}
						writes := is.InvalidWrites[write.fieldType]
						is.InvalidWrites[write.fieldType] = append(writes, write.write)
					}
					res.InitInfos[namedType] = is
				}
			}
		})
	}
}

func runZeroAllocAnalysis(st *state, res AnalysisResult) {
	logger := st.ptrState.Logger
	for _, alloc := range st.allocs {
		if isZeroAlloc(st, alloc) {
			is := res.InitInfos[alloc.typ.named]

			pos := findAllocPosition(st.ptrState.Program.Fset, alloc.instr)
			if st.ptrState.Annotations.IsIgnoredPos(pos, is.Tag) {
				logger.Infof("annotation found, ignoring %s: zero alloc at %v\n", is.Tag, pos)
				continue
			}

			ia := newZeroAlloc(&alloc, st.types, st.ptrState.Program.Fset)
			logger.Infof("%s: found zero alloc: %v at %v\n", is.Tag, alloc.instr, pos)
			is.ZeroAllocs = append(is.ZeroAllocs, ia)
			res.InitInfos[alloc.typ.named] = is
		}
	}
}

func newZeroAlloc(alloc *alloced, structToNamed map[*types.Struct]*types.Named, fset *token.FileSet) ZeroAlloc {
	named := alloc.typ.named
	if named == nil {
		n, ok := findNamedStruct(alloc.typ.strct, structToNamed)
		if !ok {
			panic(fmt.Sprintf("struct %v has no named type", alloc.typ.strct))
		}
		named = n
	}
	alloc.typ.named = named
	pos := findAllocPosition(fset, alloc.instr)

	return ZeroAlloc{Alloc: alloc.instr, Pos: pos}
}

func structInitSpecs(cfg *config.Config, target string, tag string) []config.StructInitSpec {
	var res []config.StructInitSpec
	for _, stspec := range cfg.SyntacticProblems.StructInitProblems {
		if (target == "" || funcutil.Contains(stspec.Targets, target)) &&
			(tag == "" || stspec.Tag == tag) {
			res = append(res, stspec)
		}
	}

	return res
}

// isZeroAlloc returns true if the struct allocated in alloc is a potential zero
// allocation of the specified struct.
func isZeroAlloc(st *state, alloc alloced) bool {
	for _, structNamed := range st.types {
		switch instr := alloc.instr.(type) {
		case *ssa.Alloc:
			if alloc.typ.named != nil && matchNamedStructType(alloc.typ.named, structNamed) {
				if isZeroAllocInstr(instr) {
					return true
				}
			}
		case *ssa.ChangeType:
			if matchStructType(alloc.typ.strct, structNamed.Underlying().(*types.Struct)) {
				// TODO this is safe but imprecise
				return true
			}
		case *ssa.MakeInterface:
			// TODO confirm:
			// struct converted to an interface will either have been
			// explicitly allocated previously or is initialized to the zero
			// value in the instruction itself
			if alloc.typ.named != nil && matchNamedStructType(alloc.typ.named, structNamed) {
				return true
			}
		}
	}

	return false
}

// isZeroAllocInstr returns true if there are no writes to any field of the struct that is allocated
// by alloc.
// The function only analyzes write instructions that occur in the basic block of the allocation
// instruction.
//
// This means that the function underapproximates zero allocations because it does not analyze
// all writes in the program.
func isZeroAllocInstr(alloc *ssa.Alloc) bool {
	instrs := alloc.Block().Instrs
	fieldAddrs := fieldAddrsOfAlloc(alloc, instrs)
	for _, instr := range instrs {
		store, ok := instr.(*ssa.Store)
		if !ok {
			continue
		}
		addr, ok := store.Addr.(*ssa.FieldAddr)
		if !ok {
			continue
		}

		if _, ok := fieldAddrs[addr]; ok {
			return false
		}
	}

	return true
}

// fieldAddrsOfAlloc returns all the instructions that address a field or
// sub-field of the struct allocated in alloc.
func fieldAddrsOfAlloc(alloc ssa.Value, instrs []ssa.Instruction) map[*ssa.FieldAddr]struct{} {
	fieldAddrs := make(map[*ssa.FieldAddr]struct{})
	vals := map[ssa.Value]struct{}{alloc: {}}

	for _, instr := range instrs {
		addr, ok := instr.(*ssa.FieldAddr)
		if !ok {
			continue
		}

		if _, ok := vals[addr.X]; !ok {
			continue
		}

		fieldAddrs[addr] = struct{}{}
		if typs := allStructTypes(addr.Type()); len(typs) == 0 {
			continue
		}

		// if the struct field being addressed is a struct,
		// track all future addresses to it
		vals[addr] = struct{}{}
	}

	return fieldAddrs
}

// structType contains both the named struct type
// (e.g., "[...]syntactic/structinit.structType") and its
// underlying struct type (e.g. "struct { strct: [...] }").
//
// named can be nil if the struct does not have a named type
// (i.e., it is anonymous).
type structType struct {
	strct *types.Struct
	named *types.Named
}

// allStructTypes returns the all the named and underlying types of t if it is a struct or pointer to a
// struct.
// It returns nil if t is not a struct type.
//
// A struct can have multiple struct types within it (e.g., a struct containing a field that
// itself is a struct) so the function returns multiple struct types.
func allStructTypes(t types.Type) []structType {
	return allStructTypesHelper(t, nil)
}

func allStructTypesHelper(t types.Type, typs []*types.Struct) []structType {
	var res []structType
	st, ok := isStructType(t)
	if !ok {
		return nil
	}
	// Avoid infinite recursion: don't recurse if the struct type has already been seen
	for _, seen := range typs {
		if types.Identical(st.strct, seen) {
			return nil
		}
	}
	typs = append(typs, st.strct)

	res = append(res, st)
	for i := 0; i < st.strct.NumFields(); i++ {
		fieldTyps := allStructTypesHelper(st.strct.Field(i).Type(), typs) // recursive call
		res = append(res, fieldTyps...)
	}

	return res
}

func isStructType(t types.Type) (structType, bool) {
	if t == nil {
		return structType{}, false
	}
	if t.Underlying() == nil {
		return structType{}, false
	}

	typ := t
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	if n, ok := typ.(*types.Named); ok {
		if s, ok := n.Underlying().(*types.Struct); ok {
			return structType{strct: s, named: n}, true
		}
	}

	if s, ok := typ.(*types.Struct); ok {
		return structType{strct: s, named: nil}, true
	}

	return structType{}, false
}

// alloced is a struct value that was allocated.
// The value either is the result of an allocation instruction or the struct
// that was converted to an interface.
type alloced struct {
	val   ssa.Value       // val is the allocated value.
	typ   structType      // typs are the types of val.
	instr ssa.Instruction // instr is the allocation instruction.
}

func instrCanAlloc(instr ssa.Instruction) bool {
	if instr == nil || instr.Parent() == nil {
		return false
	}

	switch instr.(type) {
	case *ssa.Alloc, *ssa.MakeInterface, *ssa.ChangeType:
		return true
	default:
		return false
	}
}

func allocsInInstr(spec config.StructInitSpec, instr ssa.Instruction, structToNamed map[*types.Struct]*types.Named) []alloced {
	var allocs []alloced
	switch instr := instr.(type) {
	case *ssa.Alloc:
		typs := allStructTypes(instr.Type())
		if len(typs) == 0 {
			return nil
		}
		for _, typ := range typs {
			if !spec.Struct.MatchType(typ.named) {
				continue
			}

			if typ.named != nil {
				structToNamed[typ.strct] = typ.named
			}
			allocs = append(allocs, alloced{val: instr, instr: instr, typ: typ})
		}

	case *ssa.MakeInterface:
		if c, ok := instr.X.(*ssa.Const); ok && c.Value == nil {
			typs := allStructTypes(instr.X.Type())
			if len(typs) == 0 {
				return nil
			}
			for _, typ := range typs {
				if !spec.Struct.MatchType(typ.named) {
					continue
				}

				if typ.named != nil {
					structToNamed[typ.strct] = typ.named
				}
				allocs = append(allocs, alloced{val: instr.X, instr: instr, typ: typ})
			}
		}

	case *ssa.ChangeType:
		// a ChangeType instruction from a struct to another struct
		// results in two "allocations":
		//   1. original struct
		//   2. resulting struct from the instruction
		valTyps := allStructTypes(instr.X.Type())
		if len(valTyps) == 0 {
			return nil
		}
		changedTyps := allStructTypes(instr.Type())
		if len(changedTyps) == 0 {
			return nil
		}
		for _, valTyp := range valTyps {
			if !spec.Struct.MatchType(valTyp.named) {
				continue
			}
			if valTyp.named != nil {
				structToNamed[valTyp.strct] = valTyp.named
			}
			allocs = append(allocs, alloced{val: instr.X, instr: instr, typ: valTyp})
		}

		for _, changedTyp := range changedTyps {
			if !spec.Struct.MatchType(changedTyp.named) {
				continue
			}
			if changedTyp.named != nil {
				structToNamed[changedTyp.strct] = changedTyp.named
			}
			allocs = append(allocs, alloced{val: instr, instr: instr, typ: changedTyp})
		}
	}

	return allocs
}

// matchNamedStructType returns true if named struct type target is either s or one of
// s's fields.
func matchNamedStructType(s types.Type, target *types.Named) bool {
	if s == target {
		return true
	}

	if st, ok := s.Underlying().(*types.Struct); ok {
		for i := 0; i < st.NumFields(); i++ {
			field := st.Field(i)
			if matchNamedStructType(field.Type(), target) { // recursive call
				return true
			}
		}
	}

	return false
}

// matchStructType returns true if struct type target is either s or one of
// s's fields.
func matchStructType(s types.Type, target *types.Struct) bool {
	if st, ok := s.(*types.Struct); ok {
		if st == target {
			return true
		}

		for i := 0; i < st.NumFields(); i++ {
			field := st.Field(i)
			if matchStructType(field.Type(), target) { // recursive call
				return true
			}
		}
	}

	return false
}

// findAllocPosition returns the best approximation of instr's position.
// This is kind of a hack because MakeInterface instructions don't have
// positions, so this returns the position of the first store instruction that
// stores the interface value.
func findAllocPosition(fset *token.FileSet, instr ssa.Instruction) token.Position {
	if instr.Pos().IsValid() {
		return fset.Position(instr.Pos())
	}

	switch instr := instr.(type) {
	case *ssa.MakeInterface:
		for _, ref := range *instr.Referrers() {
			if s, ok := ref.(*ssa.Store); ok {
				if s.Val == instr && s.Pos().IsValid() {
					return fset.Position(s.Pos())
				}
			}
		}
	case *ssa.ChangeType:
		for _, ref := range *instr.Referrers() {
			if s, ok := ref.(*ssa.Store); ok {
				if s.Val == instr && s.Pos().IsValid() {
					return fset.Position(s.Pos())
				}
			}
		}
	case *ssa.Alloc:
		return fset.Position(instr.Pos())
	default:
		panic(fmt.Errorf("invalid instruction type: %T", instr))
	}

	// TODO should this be an error?
	// panic(fmt.Errorf("no valid position found for instruction: %v in function %v", instr, instr.Parent()))
	return token.Position{}
}

type writeToField struct {
	structType structType
	fieldType  *types.Var
	write      InvalidWrite
}

func isInvalidWrite(st *state, store *ssa.Store, pos token.Position) (writeToField, bool) {
	field, ok := store.Addr.(*ssa.FieldAddr)
	if !ok {
		return writeToField{}, false
	}

	structTyp, ok := isStructType(field.X.Type())
	if !ok {
		return writeToField{}, false
	}

	named := structTyp.named
	if named == nil {
		n, ok := findNamedStruct(structTyp.strct, st.types)
		if !ok {
			return writeToField{}, false
		}
		named = n
	}

	structTyp.named = named
	fieldType := named.Underlying().(*types.Struct).Field(field.Field)
	wantVal, ok := st.fieldExpectedValue[fieldType]
	if !ok {
		// field not in spec
		return writeToField{}, false
	}

	gotVal := store.Val
	eql, err := valsEqual(gotVal, wantVal)
	if err != nil {
		panic(fmt.Errorf("unexpected store instruction %v to field %v at %v: %v", store, field, pos, err))
	}
	if eql {
		return writeToField{}, false
	}

	return writeToField{
		structType: structTyp,
		fieldType:  fieldType,
		write: InvalidWrite{
			Got:   gotVal,
			Want:  wantVal,
			Instr: store,
			Pos:   pos,
		},
	}, true
}

func valsEqual(gotVal ssa.Value, wantVal ssa.Value) (bool, error) {
	switch gotVal := gotVal.(type) {
	case *ssa.Const:
		switch wantVal := wantVal.(type) {
		case *ssa.Const:
			// compare the underlying constant values
			if gotVal.Value == wantVal.Value {
				return true, nil
			}
		case *ssa.Function:
			// if the expected function value is nil, this is a valid write
			if gotVal == nil && wantVal == nil {
				return true, nil
			}
		default:
			return false, fmt.Errorf("expected value type mismatch: want *ssa.Const or *ssa.Function, got %T", wantVal)
		}
	case *ssa.Function:
		wantFunc, ok := wantVal.(*ssa.Function)
		if !ok {
			return false, fmt.Errorf("expected value type mismatch: want *ssa.Function, got %T", wantVal)
		}
		if gotVal == wantFunc {
			return true, nil
		}
	}

	return false, nil
}

// findNamedStruct is the only way to reliably get a named struct type from a
// struct type via structToNamed because two structurally identical
// *types.Struct values may not be equal (==).
func findNamedStruct(t *types.Struct, structToNamed map[*types.Struct]*types.Named) (*types.Named, bool) {
	if n, ok := structToNamed[t]; ok {
		return n, true
	}

	for s, n := range structToNamed {
		if types.Identical(t, s) {
			return n, true
		}
	}

	return nil, false
}

func findNamedConst(program *ssa.Program, valCi config.CodeIdentifier) (*ssa.NamedConst, bool) {
	pkgs := program.AllPackages()
	for _, pkg := range pkgs {
		for _, mem := range pkg.Members {
			if c, ok := mem.(*ssa.NamedConst); ok {
				if valCi.MatchConst(c) && c.Value != nil {
					return c, true
				}
			}
		}
	}

	return nil, false
}

func findMethod(program *ssa.Program, valCi config.CodeIdentifier) (*ssa.Function, bool) {
	pkgs := program.AllPackages()
	for _, pkg := range pkgs {
		for _, mem := range pkg.Members {
			if f, ok := mem.(*ssa.Function); ok {
				if valCi.MatchPackageAndMethod(f) && f != nil {
					return f, true
				}
			}
		}
	}

	return nil, false
}

// isFiltered returns true if v is filtered according to spec or is in the standard library.
func isFiltered(spec config.StructInitSpec, f *ssa.Function) bool {
	if f == nil {
		return true
	}

	// don't analyze the standard library
	if summaries.IsStdPackageName(lang.PackageNameFromFunction(f)) {
		return true
	}

	for _, filter := range spec.Filters {
		if filter.Type != "" {
			if filter.MatchType(f.Type()) {
				return true
			}
		}

		if filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}

	return false
}

// runMustReinitChecks runs all the must-reinit checks and returns a map from named struct type to
// a possibly empty list of problems of bad reinitialization of that struct.
func runMustReinitChecks(st *state) map[*types.Named][]BadReinit {
	badReinits := map[*types.Named][]BadReinit{}
	for fn := range st.fns {
		if summaries.IsStdPackageName(lang.PackageNameFromFunction(fn)) {
			continue
		}
		lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
			if instr == nil || instr.Parent() == nil || !instr.Pos().IsValid() {
				return
			}

			if call, isCall := instr.(*ssa.Call); isCall {
				if !lang.CanType(call) {
					return
				}
				namedType := namedStructTyp(call.Type(), st.types)
				if namedType == nil {
					return
				}
				if maybeBadReinit := checkMustReinitCall(st, call); maybeBadReinit.IsSome() {
					if _, ok := badReinits[namedType]; !ok {
						badReinits[namedType] = []BadReinit{}
					}
					badReinits[namedType] = append(badReinits[namedType],
						maybeBadReinit.Value())
				}
			}
		})
	}
	return badReinits
}

// namedStructTyp extracts the types.Named type of a struct type or a pointer to a struct type.
// This is for checking reintiializations: we only check them for function that returns the proper
// named struct type.
func namedStructTyp(typ types.Type, structToNamed map[*types.Struct]*types.Named) *types.Named {
	var namedType *types.Named
	if structTyp, ok := typ.(*types.Struct); ok {
		namedType = structToNamed[structTyp]
	} else if namedTyp, ok := typ.(*types.Named); ok {
		namedType = namedTyp
	} else if ptrTyp, ok := typ.(*types.Pointer); ok {
		return namedStructTyp(ptrTyp.Elem(), structToNamed)
	}
	return namedType
}

// checkMustReinitCall checks whether the call instructions that are marked as having to
// reinitialize the fields of their output are actually doing the reinitialization.
func checkMustReinitCall(st *state, callInstr *ssa.Call) funcutil.Optional[BadReinit] {
	callees, _ := st.ptrState.ResolveCallee(callInstr)
	// Does this call need to be checked?
	mustCheckFor := []config.StructInitSpec{}
	for _, callSpec := range st.spec.MustReinits {
		for _, callee := range callees {
			if callSpec.MatchPackageAndMethod(callee.Callee) {
				mustCheckFor = append(mustCheckFor, st.spec)
			}
		}
	}

	if len(mustCheckFor) == 0 {
		return funcutil.None[BadReinit]() /* Nothing to do */
	}
	// For each spec, the statements following directly the call MUST write the fields
	// that are specified in the spec. The write statements are in the same block as the
	// call statement.
	block, index := lang.IndexInEnclosingBlock(callInstr)
	fieldsToReinit := map[string]bool{}
	for _, spec := range mustCheckFor {
		for _, fieldSpec := range spec.FieldsSet {
			fieldsToReinit[fieldSpec.Field] = true
		}
	}
	var callVal ssa.Value
	callVal = callInstr
	for i := index + 1; i < len(block.Instrs); i++ {
		instr := block.Instrs[i]
		switch instr := instr.(type) {
		case *ssa.Store:
			// Check that this is a store to a field that is tracked by the struct-init problem.
			if checkStore(instr, callVal, fieldsToReinit) {
				continue
			}
			// It can also be a store of the call returned value into another var, in which case we
			// change the callVal being tracked to properly reflect on the stores
			if instr.Val == callInstr {
				callVal = instr.Addr
				continue
			}
		case *ssa.FieldAddr:
			fieldName, _ := analysisutil.FieldAddrFieldInfo(instr)
			// Check that this is taking the address of a field that is tracked by the struct-init problem.
			if _, ok := fieldsToReinit[fieldName]; ok {
				continue
			}
		}
		// At this point, we have an instr that is not a recognized store or field addr.
		// Exit the loop to check whether it's ok because we have already reinitialized everything.
		break
	}
	if len(fieldsToReinit) == 0 {
		st.ptrState.Logger.Infof("Result of %s properly reinitialized", callInstr)
		return funcutil.None[BadReinit]() /* All checked! */
	}
	// We haven't reinit all fields. This is bad!
	return funcutil.Some(BadReinit{
		Call: callInstr,
		Pos:  st.ptrState.Program.Fset.Position(callInstr.Pos()),
	})
}

func checkStore(instr *ssa.Store, callVal ssa.Value, fieldsToReinit map[string]bool) bool {
	if field, ok := instr.Addr.(*ssa.FieldAddr); ok {
		if field.X == callVal {
			fieldName, _ := analysisutil.FieldAddrFieldInfo(field)
			if fieldsToReinit[fieldName] {
				delete(fieldsToReinit, fieldName)
				return true
			}
		}
	}
	return false
}

// FormattedReport writes res to a string and returns true if the analysis should fail.
func FormattedReport(res AnalysisResult) (string, bool) {
	failed := false

	w := &strings.Builder{}
	w.WriteString("\nstruct-init analysis results:\n")
	w.WriteString("-----------------------------\n")
	for structName, info := range res.InitInfos {
		w.WriteString(fmt.Sprintf("initialization information for %v:\n", formatutil.Bold(structName)))
		if len(info.ZeroAllocs) == 0 {
			w.WriteString(fmt.Sprintf("\t%v\n", formatutil.Green("no zero-allocations found")))
		}
		for _, alloc := range info.ZeroAllocs {
			w.WriteString(fmt.Sprintf("\t%s: %v at %v\n", formatutil.Red("zero-allocation"), alloc.Alloc, alloc.Pos))
			failed = true
		}

		for field, writes := range info.InvalidWrites {
			s := formatutil.Red("invalid writes")
			if len(writes) == 0 {
				s = formatutil.Green("no invalid writes")
			}
			w.WriteString(fmt.Sprintf("\t%s to field %v\n", s, field.Name()))
			for _, write := range writes {
				w.WriteString(fmt.Sprintf("\t\t%v (got %v, want %v) at %v\n", write.Instr, write.Got, write.Want, write.Pos))
				failed = true
			}
		}

		if len(info.BadReinits) == 0 {
			w.WriteString(fmt.Sprintf("\t%v\n", formatutil.Green("all must-reinit constraints satisfied")))
		} else {
			w.WriteString(fmt.Sprintf("\t%s\n", formatutil.Red("missing reinitializations (must-reinit not satisfied):")))
		}
		for _, badReinit := range info.BadReinits {
			w.WriteString(fmt.Sprintf("\t   after call %s at %v\n", badReinit.Call.String(), badReinit.Pos))
			failed = true
		}
	}

	return w.String(), failed
}
