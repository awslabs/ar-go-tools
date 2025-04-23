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
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// BuiltinCallSpec identifies a specific builtin call
type BuiltinCallSpec struct {
	Name string
}

// MatchAstCode matches against ast elements.
func (s BuiltinCallSpec) MatchAstCode(c AstCode) bool {
	panic("UNIMPLEMENTED")
}

// MatchSsaCode matches builtin calls
func (s BuiltinCallSpec) MatchSsaCode(_ *pointer.Result, c SsaCode) bool {
	if c.value != nil {
		builtin, isBuiltin := c.value.(*ssa.Builtin)
		if isBuiltin {
			return s.Name == builtin.Name()
		}
	}
	if c.instr != nil {
		callInstr, isCallInstr := c.instr.(ssa.CallInstruction)
		if !isCallInstr {
			return false
		}
		builtinName := handledBuiltinCallName(callInstr)
		return builtinName != "" && builtinName == s.Name
	}
	return false
}
