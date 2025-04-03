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

package structinit

import (
	"fmt"
	"go/token"
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

func runIncompleteInitAnalysis(st *state, res AnalysisResult) {
	logger := st.ptrState.Logger
	for _, alloc := range st.allocs {
		fields := zeroedFields(st, alloc)
		pos := findAllocPosition(st.ptrState.Program.Fset, alloc.instr)
		if len(fields) == 0 {
			logger.Debugf("all required fields of struct %s are initialized at %v\n",
				alloc.typ.named.String(), pos)
			continue
		}
		is := res.InitInfos[alloc.typ.named]

		if st.ptrState.Annotations.IsIgnoredPos(pos, is.Tag) {
			logger.Infof("annotation found, ignoring incomplete alloc at %v\n", pos)
			continue
		}

		ii := newIncompleteInit(alloc, fields, pos)
		report := newIncompleteInitReport(ii)
		logger.Warnf("%s\n", report.String())
		st.ptrState.Report.AddEntry(st.ptrState, config.ReportDesc{
			Tool:     config.SyntacticTool,
			Tag:      st.spec.Tag,
			Severity: st.spec.Severity,
			Content:  report,
		})
		is.IncompleteInits = append(is.IncompleteInits, ii)
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
			fieldInfo := analysisutil.FieldAddrFieldInfo(fa)
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
