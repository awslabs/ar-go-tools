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
	"maps"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
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
		state.Logger.Infof(
			"No struct-init specs matching configuration; check the tags if you expected a result")
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

	runIncompleteInitAnalysis(s, res)

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
	fns := maps.Clone(st.ReachableFunctions()) // need to clone here since we're going to delete
	var allocs []alloced
	for fn := range fns {
		if isFiltered(spec, fn) {
			st.Logger.Debugf("Skipping analyzing structs allocated in function: %v\n", fn)
			delete(fns, fn)
		} else {
			as := findAllocsInFn(spec, fn)
			allocs = append(allocs, as...)
		}
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
					return nil,
						fmt.Errorf("field name in fields-set spec should not be empty: %+v", fieldSpec)
				}
				if fieldSpec.Field == f.Name() {
					field = f
					break
				}
			}

			if field == nil {
				return nil,
					fmt.Errorf(
						"failed to find field %v in struct %v from spec: %+v",
						fieldSpec.Field,
						structTyp,
						spec)
			}
			if fieldSpec.Value.Const != "" {
				c, ok := findNamedConst(st.Program, fieldSpec.Value)
				if !ok {
					return nil,
						fmt.Errorf(
							"failed to find a named constant in the program for %v in spec: %+v",
							fieldSpec.Value,
							spec)
				}

				fieldVal[alloc.typ.named][field] = c.Value
			}

			if fieldSpec.Value.Method != "" {
				f, ok := findMethod(st.Program, fieldSpec.Value)
				if !ok {
					return nil,
						fmt.Errorf("failed to find a function in the program for %v in spec: %+v",
							fieldSpec.Value,
							spec)
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
