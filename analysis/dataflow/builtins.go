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

package dataflow

import (
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// handledBuiltins is the list of builtin function names that are internally handled by the analysis.
// You can find a complete list of builtins at:
// https://pkg.go.dev/builtin
//
// Note that new, make and panic are their own SSA instructions.
var handledBuiltins = []string{
	"ssa:wrapnilchk",
	"append",
	"len",
	"close",
	"delete",
	"println",
	"print",
	"recover",
	"cap",
	"complex",
	"imag",
	"real",
	"min",
	"max",
	"clear",
	"copy",
}

// markedBuiltins is the subset of builtins that return values that should be tracked in the analysis
var markedBuiltins = []string{"ssa:wrapnilchk", "append", "complex", "min", "max", "len", "imag", "real"}

// isHandledBuiltinCall returns true if the call is handled internally by the analysis.
func isHandledBuiltinCall(instruction ssa.CallInstruction) bool {
	if instruction.Common().Value != nil {
		name := instruction.Common().Value.Name()
		if funcutil.Contains(handledBuiltins, name) {
			return true
		}
		// Special case: the call to Error() of the builtin error interface
		if instruction.Common().IsInvoke() && instruction.Common().Method.Name() == "Error" &&
			len(instruction.Common().Args) == 0 {
			return true
		}
	}
	return false
}

func makeArgEdges(t *IntraAnalysisState, instruction ssa.CallInstruction, arg ssa.Value) {
	marks := t.getMarks(instruction, arg, "", false)
	for _, mark := range marks {
		t.summary.addBuiltinCallEdge(mark, instruction, nil)
	}
}

// makeEdgesAtBuiltinCall updates the state by adding edges from marks reaching the call instruction
// representing a call to a builtin to the builtin node.
//
// The predicate isHandledBuiltinCall should hold on the instruction argument.
func makeEdgesAtBuiltinCall(t *IntraAnalysisState, instruction ssa.CallInstruction) {
	callCommon := instruction.Common()
	if callCommon.Value != nil {
		if callCommon.Value.Name() == "recover" {
			// TODO: handle recovers
			return
		}

		for _, arg := range callCommon.Args {
			makeArgEdges(t, instruction, arg)
		}
	}
}

// doBuiltinCall returns true if the call is a builtin that is handled by default, otherwise false.
// If true is returned, the analysis may ignore the call instruction.
func markBuiltinCall(t *IntraAnalysisState, value ssa.Value, common *ssa.CallCommon,
	instr ssa.CallInstruction) bool {
	// For consistency check that the call is handled first.
	if !isHandledBuiltinCall(instr) {
		return false
	}

	if common.Value != nil {
		name := common.Value.Name()
		if funcutil.Contains(markedBuiltins, name) {
			for _, mark := range t.marksToAdd(value, instr, common) {
				t.markValue(instr, value, mark.AccessPath, mark.Mark)
			}
			return true
		}

		// Special case: the call to Error() of the builtin error interface
		if common.IsInvoke() && common.Method.Name() == "Error" && len(common.Args) == 0 {
			simpleTransfer(t, instr, common.Value, value)
		}
	}
	return true
}

// doBuiltinCall returns true if the call is a builtin that is handled by default, otherwise false.
// If true is returned, the analysis may ignore the call instruction.
func doBuiltinCall(t *IntraAnalysisState, callValue ssa.Value, callCommon *ssa.CallCommon,
	instruction ssa.CallInstruction) {
	// For consistency check that the call is handled first.
	if !isHandledBuiltinCall(instruction) {
		return
	}
	// Builtins that have no effect here:
	// "cap", "complex", "min", "max", "len", "imag", "real", "close", "delete", "clear", "println", "print", "recover"
	if callCommon.Value != nil {
		switch callCommon.Value.Name() {
		// for append, copy we simply propagate the taint like in a binary operator
		case "ssa:wrapnilchk":
			for _, arg := range callCommon.Args {
				simpleTransfer(t, instruction, arg, callValue)
			}
		case "append":
			if len(callCommon.Args) == 2 {
				sliceV := callCommon.Args[0]
				dataV := callCommon.Args[1]
				simpleTransfer(t, instruction, dataV, sliceV)
			}
		case "copy":
			if len(callCommon.Args) == 2 {
				src := callCommon.Args[1]
				dst := callCommon.Args[0]
				// copy transfers from source to destination
				simpleTransfer(t, instruction, src, dst)
			}
		default:
			// Special case: the call to Error() of the builtin error interface
			if callCommon.IsInvoke() &&
				callCommon.Method.Name() == "Error" &&
				len(callCommon.Args) == 0 {
				simpleTransfer(t, instruction, callCommon.Value, callValue)
			}
		}
	}
	return
}
