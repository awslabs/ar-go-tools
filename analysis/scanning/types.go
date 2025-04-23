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
	"go/types"
	"regexp"

	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// TypeSpec specifies a type to match
type TypeSpec struct {
	CommonSpec
	Type *regexp.Regexp
}

// MatchAstCode matches ast elements
func (s TypeSpec) MatchAstCode(a AstCode) bool { panic("UNIMPLEMENTED") }

// MatchSsaCode returns true when the type of the node provided matches the type.
// The type is extracted first from the ssa.Value is available.
func (s TypeSpec) MatchSsaCode(p *pointer.Result, c SsaCode) bool {
	var typ types.Type
	if c.value != nil {
		typ = c.value.Type()
	} else {
		return false // canot extract the type
	}
	if c.instr != nil && !s.matchEnclosingContext(c.instr.Parent()) {
		return false
	}
	if typ == nil {
		return false
	}
	if named, ok := typ.(*types.Named); ok {
		if named == nil { // extra check is needed because the *types.Named value can be nil, even if typ != nil
			return false
		}
		if named.Obj() != nil && named.Obj().Pkg() != nil {
			typePkgPath := named.Obj().Pkg().Path()
			typeName := named.Obj().Name()
			return s.CommonSpec.Package.MatchString(typePkgPath) && s.Type.MatchString(typeName)
		}
	}

	return s.Type.MatchString(typ.String())

}
