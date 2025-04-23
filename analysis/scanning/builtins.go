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

package scanning

import (
	"regexp"

	"golang.org/x/tools/go/ssa"
)

// handledBuiltins is the list of builtin function names that are internally handled by the analysis.
// You can find a complete list of builtins at:
// https://pkg.go.dev/builtin
//
// Note that new, make and panic are their own SSA instructions.
var handledBuiltins = map[string]bool{
	"ssa:wrapnilchk": true,
	"append":         true,
	"len":            true,
	"close":          true,
	"delete":         true,
	"println":        true,
	"print":          true,
	"recover":        true,
	"cap":            true,
	"complex":        true,
	"imag":           true,
	"real":           true,
	"min":            true,
	"max":            true,
	"clear":          true,
	"copy":           true,
}

func handledBuiltinCallName(instruction ssa.CallInstruction) string {
	if instruction.Common().Value != nil {
		name := instruction.Common().Value.Name()
		if handledBuiltins[name] {
			return name
		}
		// Special case: the call to Error() of the builtin error interface
		if instruction.Common().IsInvoke() && instruction.Common().Method.Name() == "Error" &&
			len(instruction.Common().Args) == 0 {
			return "Error"
		}
	}
	return ""
}

// IsHandledBuiltinCall returns true if the call is handled internally by the analysis.
func IsHandledBuiltinCall(instruction ssa.CallInstruction) bool {
	return handledBuiltinCallName(instruction) != ""
}

// MatchesHandledBuiltinCall returns true if the provided regex matches some builtin that is
// handled by the analysis
func MatchesHandledBuiltinCall(r *regexp.Regexp) bool {
	for handledBuiltinName := range handledBuiltins {
		if r.MatchString(handledBuiltinName) {
			return true
		}
	}
	return false
}
