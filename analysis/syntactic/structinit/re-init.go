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
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

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
			fieldInfo := analysisutil.FieldAddrFieldInfo(instr)
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
			fieldInfo := analysisutil.FieldAddrFieldInfo(field)
			if fieldsToReinit[fieldInfo.FieldName] {
				delete(fieldsToReinit, fieldInfo.FieldName)
				return true
			}
		}
	}
	return false
}
