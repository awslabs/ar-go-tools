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

	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// StructFieldSpec is a specification for a struct field (accessing a specific field of a struct
// of a specific type)
type StructFieldSpec struct {
	CommonSpec
	Type  *regexp.Regexp
	Field *regexp.Regexp
	Write bool
}

// MatchAstCode matches an ast code descriptor
func (s StructFieldSpec) MatchAstCode(a AstCode) bool { panic("UNIMPLEMENTED") }

// MatchSsaCode returns true when the node is a field acess over a struct type matching the spec
//
//gocyclo:ignore
func (s StructFieldSpec) MatchSsaCode(p *pointer.Result, c SsaCode) bool {
	if c.instr == nil {
		return false
	}

	if !s.matchEnclosingContext(c.instr.Parent()) {
		return false
	}

	var fieldInfo analysisutil.FieldInfo
	var packageName string
	var typeName string
	var err error
	isField := false
	switch fieldAccess := c.instr.(type) {
	case *ssa.Field:
		if s.Write {
			return false // only reading from field here
		}
		isField = true
		fieldInfo = analysisutil.FieldFieldInfo(fieldAccess)
		packageName, typeName, err = analysisutil.FindEltTypePackage(fieldAccess.X.Type(), "%s")
		if err != nil {
			return false
		}
	case *ssa.FieldAddr:
		if s.Write {
			return false // only reading from field here
		}
		isField = true
		fieldInfo = analysisutil.FieldAddrFieldInfo(fieldAccess)
		packageName, typeName, err = analysisutil.FindEltTypePackage(fieldAccess.X.Type(), "%s")
		if err != nil {
			return false
		}
	case *ssa.Store:
		if !s.Write {
			return false // storing here
		}
		if fieldAddr, isFieldAddr := fieldAccess.Addr.(*ssa.FieldAddr); isFieldAddr {
			isField = true
			fieldInfo = analysisutil.FieldAddrFieldInfo(fieldAddr)
			packageName, typeName, err = analysisutil.FindEltTypePackage(fieldAddr.X.Type(), "%s")
			if err != nil {
				return false
			}
		}
	}
	if !isField {
		return false
	}

	return s.Type.MatchString(typeName) &&
		s.Field.MatchString(fieldInfo.FieldName) &&
		s.Package.MatchString(packageName)
}
