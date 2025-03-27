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
	// IncompleteInits is a list of the incomplete initializations of the struct.
	IncompleteInits []IncompleteInit
	// InvalidWrites is a mapping of the struct field to all the invalid writes
	// to that field.
	InvalidWrites map[*types.Var][]InvalidWrite
	// BadReinits is a list of bad reinitializations
	BadReinits []BadReinit
}

// IncompleteInit is an incomplete initialization of a struct with some fields that should be
// initialized according to the spec but are not.
//
// If the spec does not specify any fields, the allocation will be considered "complete",
// even if no fields are actually initialized in the code.
// We only track fields that are initialized in the same basic block as the allocation.
type IncompleteInit struct {
	// Alloc is the allocation instruction.
	Alloc ssa.Instruction
	// Struct is the struct that was allocated.
	Struct *types.Named
	// InvalidZeroedFields are the names of the fields of the struct that should be initialized
	// according to the spec, but are not.
	// Go implicitly initializes them to the zero value of the type, hence the name "zeroed" fields.
	InvalidZeroedFields []string
	// Pos is the position of the instruction.
	Pos token.Position
}

func (ia IncompleteInit) String() string {
	return fmt.Sprintf("incomplete init of struct %v with invalid zeroed fields [%v] at %v",
		ia.Struct, strings.Join(ia.InvalidZeroedFields, ", "), ia.Pos)
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
	st.Logger.PushContext(formatutil.Yellow(spec.Tag))
	defer st.Logger.PopContext()

	s, err := newState(spec, st)
	if err != nil {
		return fmt.Errorf("failed to initialize analysis: %v", err)
	}

	runIncompleteAllocAnalysis(s, res)

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
// A spec can match multiple structs via regexes.
type state struct {
	// spec is the spec being analyzed currently.
	spec config.StructInitSpec
	// allocs are all the values of the struct(s) to track that were allocated in the program.
	allocs []alloced
	// fieldExpectedValue is a mapping of the named spec-matching struct to its fields with the
	// concrete value the field should be initialized to according to the spec.
	//
	// For now, the value can only be:
	// - *ssa.NamedConst
	// - *ssa.Function
	fieldExpectedValue map[*types.Named]map[*types.Var]ssa.Value

	fns      map[*ssa.Function]bool
	ptrState *ptr.State
}

// newState initializes a new analysis state to analyze all structs in the program that match the
// struct(s) specified in the spec.
func newState(spec config.StructInitSpec, st *ptr.State) (*state, error) {
	fns := st.ReachableFunctions()
	var allocs []alloced
	for fn := range fns {
		if isFiltered(spec, fn) {
			st.Logger.Debugf("Skipping analyzing structs allocated in function: %v\n", fn)
			delete(fns, fn)
		}

		as := findAllocsInFn(spec, fn)
		allocs = append(allocs, as...)
	}
	fieldVal := make(map[*types.Named]map[*types.Var]ssa.Value)

	for _, alloc := range allocs {
		structTyp := alloc.typ.strct
		if _, ok := fieldVal[alloc.typ.named]; ok {
			continue
		}
		fieldVal[alloc.typ.named] = make(map[*types.Var]ssa.Value)

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

				fieldVal[alloc.typ.named][field] = c.Value
			}

			if fieldSpec.Value.Method != "" {
				f, ok := findMethod(st.Program, fieldSpec.Value)
				if !ok {
					return nil, fmt.Errorf("failed to find a function in the program for %v in spec: %+v", fieldSpec.Value, spec)
				}

				fieldVal[alloc.typ.named][field] = f
			}
		}
	}

	return &state{
		spec:               spec,
		allocs:             allocs,
		fieldExpectedValue: fieldVal,
		ptrState:           st,
		fns:                fns,
	}, nil
}

// findAllocsInFn returns all the values of the struct to track according to spec that were
// allocated in fn.
func findAllocsInFn(spec config.StructInitSpec, fn *ssa.Function) []alloced {
	var allocs []alloced

	lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
		if !instrCanAlloc(instr) {
			return
		}

		structAllocs := allocsInInstr(spec, instr)
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

func runIncompleteAllocAnalysis(st *state, res AnalysisResult) {
	logger := st.ptrState.Logger
	for _, alloc := range st.allocs {
		fields := zeroedFields(st, alloc)
		pos := findAllocPosition(st.ptrState.Program.Fset, alloc.instr)
		if len(fields) == 0 {
			logger.Debugf("all required fields of allocated struct are initialized: %v at %v\n",
				alloc.typ.named.String(), pos)
			continue
		}
		is := res.InitInfos[alloc.typ.named]

		if st.ptrState.Annotations.IsIgnoredPos(pos, is.Tag) {
			logger.Infof("annotation found, ignoring %s: incomplete alloc at %v\n", is.Tag, pos)
			continue
		}

		ia := newIncompleteInit(alloc, fields, pos)
		logger.Infof("%s: found %v", is.Tag, ia)
		is.IncompleteInits = append(is.IncompleteInits, ia)
		res.InitInfos[alloc.typ.named] = is
	}
}

func newIncompleteInit(alloc alloced, fields []string, pos token.Position) IncompleteInit {
	named := alloc.typ.named
	if named == nil {
		panic(fmt.Sprintf("struct %v has no named type", alloc.typ.strct))
	}

	return IncompleteInit{
		Alloc:               alloc.instr,
		Struct:              alloc.typ.named,
		InvalidZeroedFields: fields,
		Pos:                 pos,
	}
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

// zeroedFields returns all the field names of a struct specified in the spec that
// should be initialized to a non-zero value, but are left uninitialized (i.e., implicitly set to
// the zero value).
//
// The analysis determines a field to be zeroed if there are no writes to it in the block in
// which it is allocated. This is an underapproximation.
//
//gocyclo:ignore
func zeroedFields(st *state, alloc alloced) []string {
	// NOTE Edge case:
	// If the struct type that was allocated (alloc.typ) is a field of a struct and a pointer, then
	// that struct will be explicitly allocated later (different alloc.val) and we do not need to
	// track the zeroed fields in this call to zeroedFields.
	//
	// The allocation of the field's struct value occurs explicitly because since the zero value of
	// a pointer is nil, the struct has to be initialized (allocated) in order to be written to.
	//
	// If the spec-matching struct pointer field is never explicitly allocated, it is "sound" to
	// consider the allocation of the enclosing struct as "complete" (i.e. having no zero values of
	// any struct fields we specified in the spec). This is because the struct itself is implicitly
	// initialized to `nil` so de-referencing it in order to write to a field would cause a panic.
	//
	// E.g.
	// ----
	// The Go code:
	// type nestedTargetPtr struct {
	//     t *target // <- spec-matching struct that is a pointer
	// }
	// var ex1 nestedTargetPtr
	// ex2 := nestedTargetPtr{t: &target{x: 1}}
	//
	// Becomes this SSA:
	// t25 = make any <- nestedTargetPtr (nestedTargetPtr{}:nestedTargetPtr) any // <- this is ex1: field `t *target` is implicitly set to nil
	// ...
	// t32 = local nestedTargetPtr (ex2)  *nestedTargetPtr // <- don't track field addresses of this struct (ex2)
	// t33 = &t32.t [#0]                          **target // <- nestedTargetPtr.t is nil
	// t34 = new target (complit)                  *target // <- we only care about this one: a different alloc.val
	// t35 = &t34.x [#0]                              *int
	// *t35 = 1:int                                        // <- write to target.x occurs here
	// *t33 = t34                                          // <- nestedTargetPtr.t = target
	if alloc.typ.isField && alloc.typ.isPtr {
		return nil
	}

	fieldIsZeroed := make(map[string]bool)
	for _, fs := range st.spec.FieldsSet {
		fieldIsZeroed[fs.Field] = true
	}
	// transitiveFieldAddrs are the transitive field address instructions of the spec-matching
	// struct that is explicitly or implicitly allocated in alloc.
	transitiveFieldAddrs := make(map[*ssa.FieldAddr]struct{})
	block, index := lang.IndexInEnclosingBlock(alloc.instr)
	for _, instr := range block.Instrs[index:] {
		switch instr := instr.(type) {
		case *ssa.FieldAddr:
			// Initialize transitiveFieldAddrs:
			// The struct of the field that is addressed must be the same as the struct value that
			// was allocated.
			if instr.X == alloc.val {
				transitiveFieldAddrs[instr] = struct{}{}
				continue
			}
			fa, ok := instr.X.(*ssa.FieldAddr)
			if !ok {
				continue
			}
			if _, ok := transitiveFieldAddrs[fa]; !ok {
				continue
			}
			transitiveFieldAddrs[instr] = struct{}{}
		case *ssa.Store:
			fa, ok := instr.Addr.(*ssa.FieldAddr)
			if !ok {
				continue
			}
			fieldInfo, ok := analysisutil.FieldAddrFieldInfo(fa)
			if !ok {
				continue
			}
			if _, ok := transitiveFieldAddrs[fa]; !ok {
				continue
			}
			if typ, ok := isStructType(instr.Val.Type()); ok {
				if st.spec.Struct.MatchType(typ.named) {
					continue
				}
			}
			fieldIsZeroed[fieldInfo.FieldName] = false
		}
	}

	var res []string
	for name, isZeroed := range fieldIsZeroed {
		if isZeroed {
			res = append(res, name)
		}
	}

	return res
}

// structType contains both the named struct type
// (e.g., "<pkg-path>/structinit.structType") and its
// underlying struct type (e.g. "struct { strct: [...] }").
//
// named can be nil if the struct does not have a named type
// (i.e., it is anonymous).
type structType struct {
	strct   *types.Struct
	named   *types.Named
	isPtr   bool
	isField bool
}

func (t structType) String() string {
	name := "<anon>"
	if t.named != nil {
		name = t.named.String()
	}
	ptr := ""
	if t.isPtr {
		ptr = "ptr to "
	}
	return fmt.Sprintf("%s%s %s (field? %v)", ptr, name, t.strct.String(), t.isField)
}

// allStructTypes returns the all the named and underlying types of t if it is a struct or pointer to a
// struct.
// It returns nil if t is not a struct type.
//
// A struct can have multiple struct types within it (e.g., a struct containing a field that
// itself is a struct) so the function returns multiple struct types.
func allStructTypes(t types.Type) []structType {
	return allStructTypesHelper(t, nil, false)
}

func allStructTypesHelper(t types.Type, typs []*types.Struct, isField bool) []structType {
	var res []structType
	st, ok := isStructTypeHelper(t, isField)
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
		fieldTyps := allStructTypesHelper(st.strct.Field(i).Type(), typs, true) // recursive call
		res = append(res, fieldTyps...)
	}

	return res
}

// isStructType returns the structType of t and true if t is a struct type, otherwise false.
func isStructType(t types.Type) (structType, bool) {
	return isStructTypeHelper(t, false)
}

// isStructFieldType returns the structType of struct field type t and true if t is a struct type,
// otherwise false.
func isStructFieldType(t types.Type) (structType, bool) {
	return isStructTypeHelper(t, true)
}

func isStructTypeHelper(t types.Type, isField bool) (structType, bool) {
	if t == nil {
		return structType{}, false
	}
	if t.Underlying() == nil {
		return structType{}, false
	}

	typ := t
	isPtr := false
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
		isPtr = true
	}

	if n, ok := typ.(*types.Named); ok {
		if s, ok := n.Underlying().(*types.Struct); ok {
			return structType{strct: s, named: n, isPtr: isPtr, isField: isField}, true
		}
	}

	if s, ok := typ.(*types.Struct); ok {
		return structType{strct: s, named: nil, isPtr: isPtr, isField: isField}, true
	}

	return structType{}, false
}

// alloced is a struct value that was allocated.
// The value either is the result of an allocation instruction or the struct
// that was converted to an interface.
type alloced struct {
	val   ssa.Value       // val is the allocated value.
	instr ssa.Instruction // instr is the allocation instruction.
	typ   structType      // typ is the type of the struct that was allocated (may be implicit).
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

// allocsInInstr returns all of the allocations in instr that explicitly or implicitly allocate a
// struct matched by the spec.
//
// An implicit allocation is when a spec-matching struct is "allocated" because it is a field of a
// struct (e.g., any allocation of `struct {f match}` results in an implicit allocation of
// struct `match{}` because `match` is implicitly initialized to the zero value).
// If a field of type spec-matching struct is a pointer (e.g., type struct nomatch{f *match}), then
// it is not allocated because if the field is written to, the *ssa.Alloc instruction will occur
// explicitly later on.
//
// This function may return multiple "allocations" if the struct allocated has multiple fields of
// type struct that match, or if the instruction itself results in multiple allocations (e.g.,
// *ssa.ChangeType).
func allocsInInstr(spec config.StructInitSpec, instr ssa.Instruction) []alloced {
	var allocs []alloced
	addAllocs := func(allocedVal ssa.Value) {
		typs := structTypesThatMatchSpec(spec, allocedVal.Type())
		for _, typ := range typs {
			if typ.named == nil {
				continue
			}
			allocs = append(allocs, alloced{val: allocedVal, instr: instr, typ: typ})
		}
	}

	switch instr := instr.(type) {
	case *ssa.Alloc:
		addAllocs(instr)

	case *ssa.MakeInterface:
		if c, ok := instr.X.(*ssa.Const); ok && c.Value == nil {
			addAllocs(instr.X)
		}

	case *ssa.ChangeType:
		// a ChangeType instruction from a struct to another struct
		// results in two "allocations":
		//   1. original struct
		//   2. resulting struct from the instruction
		addAllocs(instr.X)
		addAllocs(instr)
	}

	return allocs
}

// structTypesThatMatchSpec returns all the struct types in t (transitive: fields can be struct
// types too) that match the struct specified in spec.
func structTypesThatMatchSpec(spec config.StructInitSpec, t types.Type) []structType {
	var res []structType
	typs := allStructTypes(t)
	if len(typs) == 0 {
		return nil
	}

	for _, typ := range typs {
		if !spec.Struct.MatchType(typ.named) {
			continue
		}

		res = append(res, typ)
	}

	return res
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

	structTyp, ok := isStructFieldType(field.X.Type())
	if !ok {
		return writeToField{}, false
	}

	if structTyp.named == nil {
		named, ok := findNamedStruct(field.X, store.Block())
		if !ok {
			return writeToField{}, false
		}
		structTyp.named = named
	}

	fieldType := structTyp.named.Underlying().(*types.Struct).Field(field.Field)
	wantVal, ok := st.fieldExpectedValue[structTyp.named][fieldType]
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

// findNamedStruct finds the named struct type that has the same value as structVal in block.
//
// It is useful when an anonymous struct gets converted to a named spec-matching struct.
func findNamedStruct(structVal ssa.Value, block *ssa.BasicBlock) (*types.Named, bool) {
	for _, instr := range block.Instrs {
		switch instr := instr.(type) {
		case *ssa.UnOp:
			// If instr reads from structVal, it becomes the result
			if instr.X == structVal && instr.Op == token.MUL {
				structVal = instr
			}
		case *ssa.ChangeType:
			if instr.X == structVal {
				structVal = instr

				if typ, ok := isStructType(structVal.Type()); ok {
					if typ.named != nil {
						return typ.named, true
					}
				}
			}
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
				namedType := namedStructTyp(call.Type())
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
func namedStructTyp(typ types.Type) *types.Named {
	var namedType *types.Named
	if _, ok := typ.(*types.Struct); ok {
		namedType = nil
	} else if namedTyp, ok := typ.(*types.Named); ok {
		namedType = namedTyp
	} else if ptrTyp, ok := typ.(*types.Pointer); ok {
		return namedStructTyp(ptrTyp.Elem())
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
			fieldInfo, ok := analysisutil.FieldAddrFieldInfo(instr)
			if !ok {
				continue
			}
			// Check that this is taking the address of a field that is tracked by the struct-init problem.
			if _, ok := fieldsToReinit[fieldInfo.FieldName]; ok {
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
			fieldInfo, ok := analysisutil.FieldAddrFieldInfo(field)
			if !ok {
				return false
			}
			if fieldsToReinit[fieldInfo.FieldName] {
				delete(fieldsToReinit, fieldInfo.FieldName)
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
		if len(info.IncompleteInits) == 0 {
			w.WriteString(fmt.Sprintf("\t%v\n", formatutil.Green("no incomplete allocations found")))
		}
		for _, alloc := range info.IncompleteInits {
			w.WriteString(fmt.Sprintf("\t%s: %v at %v\n", formatutil.Red("incomplete allocation"), alloc.Alloc, alloc.Pos))
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
