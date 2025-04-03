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
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"golang.org/x/tools/go/ssa"
)

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
						report := newInvalidWriteReport(write, namedType, pos)
						logger.Warnf(report.String())
						st.ptrState.Report.AddEntry(st.ptrState, config.ReportDesc{
							Tool:     config.SyntacticTool,
							Tag:      st.spec.Tag,
							Severity: st.spec.Severity,
							Content:  report,
						})
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
