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
	"go/ast"
	"regexp"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// TODO: an ssacode to identify a ssa.Function

// An SsaCode is either a value or an instruction (or both). Optionally, there
// can be additional information specifying for example the callee of a call instruction,
// making the SsaCode more predice that only the instruction or value.
type SsaCode struct {
	instr      ssa.Instruction
	value      ssa.Value
	calleeInfo *lang.CalleeInfo
	indirect   bool // the value is indirectly referencing another one. e.g a call arg
}

// NewCallInstrCode return an ssa code with a instruction can some callee info
func NewCallInstrCode(i ssa.Instruction, c *lang.CalleeInfo) SsaCode {
	code := NewInstrCode(i)
	code.calleeInfo = c
	return code
}

// Instr returns the instruction of the ssacode, which can be nil for value-codes
func (c SsaCode) Instr() ssa.Instruction {
	return c.instr
}

// NewSsaNodeCode returns an SsaCode for an ssa.Node
func NewSsaNodeCode(n ssa.Node) SsaCode {
	s := SsaCode{}
	if instr, isInstr := n.(ssa.Instruction); isInstr {
		s.instr = instr
	}
	if val, isVal := n.(ssa.Value); isVal {
		s.value = val
	}
	return s
}

// NewValueCode returns an ssa code that is just a value
func NewValueCode(v ssa.Value, indirect bool) SsaCode {
	if instr, isAlsoInstr := v.(ssa.Instruction); isAlsoInstr {
		return SsaCode{value: v, instr: instr, indirect: indirect}
	}
	return SsaCode{value: v, indirect: indirect}
}

// NewInstrCode returns an ssa code that is just an instruction
func NewInstrCode(i ssa.Instruction) SsaCode {
	if value, isAlsoValue := i.(ssa.Value); isAlsoValue {
		return SsaCode{value: value, instr: i}
	}
	return SsaCode{instr: i}
}

// AstCode contains information recorded from the ast that can be used to match
//
// TODO for now, just a wrapper around node
type AstCode struct {
	node ast.Node
}

// NewAstCode returns a new ast code for one node
func NewAstCode(node ast.Node) AstCode {
	return AstCode{node}
}

// A CodeSpec is any object that can match an SsaCode and an AstCode
type CodeSpec interface {
	MatchSsaCode(*pointer.Result, SsaCode) bool
	MatchAstCode(AstCode) bool
}

type calleeInfo struct {
	method string
	pkg    string
	recv   string
}

func calleeAliases(pointers *pointer.Result, node *ssa.Call) []calleeInfo {
	aliases := []calleeInfo{}
	if pointers == nil {
		return aliases
	}
	ptr, hasAliases := pointers.Queries[node.Call.Value]
	if !hasAliases {
		return aliases
	}
	for _, label := range ptr.PointsTo().Labels() {
		funcName := label.Value().Name()
		funcPackage := analysisutil.FindValuePackage(label.Value())
		if funcPackage.IsSome() {
			aliases = append(aliases, calleeInfo{
				pkg:    funcPackage.Value(),
				method: funcName,
				recv:   "",
			})
		}
	}
	return aliases
}

// CommonSpec groupds elements that are common to many specs
type CommonSpec struct {
	Package        *regexp.Regexp
	ContextPackage *regexp.Regexp
	ContextMethod  *regexp.Regexp
}

// MatchCallerContext matches the caller's context with the ContextPackage and ContextMethod
// of the CommonSpec.
// TODO: add more context to match
func (c CommonSpec) matchEnclosingContext(caller *ssa.Function) bool {
	if caller == nil {
		return true // no context => match
	}
	if c.ContextPackage != nil {
		if caller.Pkg != nil && !c.ContextPackage.MatchString(caller.Pkg.Pkg.Path()) {
			return false
		}
	}
	return c.ContextMethod.MatchString(caller.Name())
}
