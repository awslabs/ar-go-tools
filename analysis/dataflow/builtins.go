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

import "golang.org/x/tools/go/ssa"

func isHandledBuiltinCall(instruction ssa.CallInstruction) bool {
	if instruction.Common().Value != nil {
		switch instruction.Common().Value.Name() {
		// for append, copy we simply propagate the taint like in a binary operator
		case "ssa:wrapnilchk":
			return true
		case "append", "len", "close", "delete", "println", "print", "recover", "cap":
			return true

		// Complex numbers
		case "complex", "imag", "real":
			return true

		// starting from go1.21
		case "min", "max", "clear":
			return true

		case "copy":
			if len(instruction.Common().Args) == 2 {
				return true
			}
			return false

		default:
			// Special case: the call to Error() of the builtin error interface
			if instruction.Common().IsInvoke() && instruction.Common().Method.Name() == "Error" &&
				len(instruction.Common().Args) == 0 {
				return true
			}
			return false
		}
	}
	return false
}

// doBuiltinCall returns true if the call is a builtin that is handled by default, otherwise false.
// If true is returned, the analysis may ignore the call instruction.
//
//gocyclo:ignore
func doBuiltinCall(t *IntraAnalysisState, callValue ssa.Value, callCommon *ssa.CallCommon,
	instruction ssa.CallInstruction) bool {
	// For consistency check that the call is handled first.
	if !isHandledBuiltinCall(instruction) {
		return false
	}
	if callCommon.Value != nil {
		switch callCommon.Value.Name() {
		// for append, copy we simply propagate the taint like in a binary operator
		case "ssa:wrapnilchk":
			for _, arg := range callCommon.Args {
				simpleTransfer(t, instruction, arg, callValue)
			}
			return true
		case "append":
			if len(callCommon.Args) == 2 {
				sliceV := callCommon.Args[0]
				dataV := callCommon.Args[1]
				simpleTransfer(t, instruction, sliceV, callValue)
				simpleTransfer(t, instruction, dataV, sliceV)
				simpleTransfer(t, instruction, dataV, callValue)
				return true
			}
			return false

		case "copy":
			if len(callCommon.Args) == 2 {
				src := callCommon.Args[1]
				dst := callCommon.Args[0]
				// copy transfers from source to destination
				simpleTransfer(t, instruction, src, dst)
				return true
			}
			return false

		case "cap":
			// taking the capacity does not propagate taint
			return true

		case "complex", "min", "max":
			if len(callCommon.Args) == 2 {
				f1 := callCommon.Args[1]
				f2 := callCommon.Args[0]
				simpleTransfer(t, instruction, f1, callValue)
				simpleTransfer(t, instruction, f2, callValue)
				return true
			}
			return false

		// for len, imag, real we also propagate the taint. This may not be necessary
		case "len", "imag", "real":
			for _, arg := range callCommon.Args {
				simpleTransfer(t, instruction, arg, callValue)
			}
			return true

		// for close, delete, nothing is propagated
		case "close", "delete", "clear":
			return true

		// the builtin println doesn't return anything
		case "println", "print":
			return true

		// for recover, we will need some form of panic analysis
		case "recover":
			// TODO: handler recovers. Analysis is unsound with recovers.
			// NOTE: Unsoundness is reported by reportUnsoundFeatures
			return true
		default:
			// Special case: the call to Error() of the builtin error interface
			if callCommon.IsInvoke() &&
				callCommon.Method.Name() == "Error" &&
				len(callCommon.Args) == 0 {
				simpleTransfer(t, instruction, callCommon.Value, callValue)
				return true
			}
			return false
		}
	}
	return false
}
