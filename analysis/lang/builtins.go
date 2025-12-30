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

package lang

// HandledBuiltins is the list of builtin function names that are internally handled by the analysis.
// You can find a complete list of builtins at:
// https://pkg.go.dev/builtin
//
// Note that new, make and panic are their own SSA instructions.
var HandledBuiltins = map[string]bool{
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

// UnsafeBuiltins lists the builtins that are from the unsafe package
var UnsafeBuiltins = map[string]bool{
	"Alignof":     true,
	"Offsetof":    true,
	"Sizeof":      true,
	"Pointer":     true,
	"SliceData":   true,
	"String":      true,
	"StringData":  true,
	"Slice":       true,
	"Add":         true,
	"IntegerType": true,
}
