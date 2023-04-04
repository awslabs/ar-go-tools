package dataflow

import "golang.org/x/tools/go/ssa"

func isHandledBuiltinCall(instruction ssa.CallInstruction) bool {
	if instruction.Common().Value != nil {
		switch instruction.Common().Value.Name() {
		// for append, copy we simply propagate the taint like in a binary operator
		case "ssa:wrapnilchk":
			return true
		case "append":
			return true

		case "copy":
			if len(instruction.Common().Args) == 2 {
				return true
			} else {
				return false
			}

		// for len, we also propagate the taint. This may not be necessary
		case "len":
			return true

		// for close, delete, nothing is propagated
		case "close", "delete":
			return true

		// the builtin println doesn't return anything
		case "println":
			return true

		// for recover, we will need some form of panic analysis
		case "recover":
			return true
		default:
			// Special case: the call to Error() of the builtin error interface
			if instruction.Common().IsInvoke() && instruction.Common().Method.Name() == "Error" &&
				len(instruction.Common().Args) == 0 {
				return true
			} else {
				return false
			}
		}
	} else {
		return false
	}
}

// doBuiltinCall returns true if the call is a builtin that is handled by default, otherwise false.
// If true is returned, the analysis may ignore the call instruction.
func doBuiltinCall(t *analysisState, callValue ssa.Value, callCommon *ssa.CallCommon,
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
				simpleTransitiveMarkPropagation(t, instruction, arg, callValue)
			}
			return true
		case "append":
			if len(callCommon.Args) == 2 {
				sliceV := callCommon.Args[0]
				dataV := callCommon.Args[1]
				simpleTransitiveMarkPropagation(t, instruction, sliceV, callValue)
				simpleTransitiveMarkPropagation(t, instruction, dataV, callValue)
				return true
			} else {
				return false
			}

		case "copy":
			if len(callCommon.Args) == 2 {
				src := callCommon.Args[1]
				dst := callCommon.Args[0]
				simpleTransitiveMarkPropagation(t, instruction, src, dst)
				return true
			} else {
				return false
			}

		// for len, we also propagate the taint. This may not be necessary
		case "len":
			for _, arg := range callCommon.Args {
				simpleTransitiveMarkPropagation(t, instruction, arg, callValue)
			}
			return true

		// for close, delete, nothing is propagated
		case "close", "delete":
			return true

		// the builtin println doesn't return anything
		case "println":
			return true

		// for recover, we will need some form of panic analysis
		case "recover":
			t.cache.Err.Printf("Encountered recover at %s, the analysis may be unsound.\n",
				instruction.Parent().Prog.Fset.Position(instruction.Pos()))
			return true
		default:
			// Special case: the call to Error() of the builtin error interface
			// TODO: double check
			if callCommon.IsInvoke() &&
				callCommon.Method.Name() == "Error" &&
				len(callCommon.Args) == 0 {
				simpleTransitiveMarkPropagation(t, instruction, callCommon.Value, callValue)
				return true
			} else {
				return false
			}
		}
	} else {
		return false
	}
}
