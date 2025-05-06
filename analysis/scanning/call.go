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

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// CallSpec identifies a specifc call
type CallSpec struct {
	CommonSpec
	// Interface matches interface types. Can be nil.
	Interface *regexp.Regexp
	// Method matches method / function name. **Cannot be nil**.
	Method *regexp.Regexp
	// ReceiverType matches receivers. Can be nil.
	ReceiverType *regexp.Regexp
	// ValueMatch matches the ssa value's string. Can be nil.
	ValueMatch *regexp.Regexp
}

// MatchAstCode matches ast elements
func (s CallSpec) MatchAstCode(a AstCode) bool { panic("UNIMPLEMENTED") }

// MatchSsaCode returns true when the node provided is a call to a function that matches
// the spec.
func (s CallSpec) MatchSsaCode(p *pointer.Result, c SsaCode) bool {
	// A call is at least an instruction
	if c.instr == nil || c.parent != nil {
		return false
	}

	call, isCall := c.instr.(ssa.CallInstruction)
	if !isCall || call == nil {
		return false
	}

	if s.ValueMatch != nil && call.Value() != nil && !s.ValueMatch.MatchString(call.String()) {
		return false
	}

	if !lang.SafeUnderlyingCall(call) {
		return false
	}

	// Check context.
	if !s.matchEnclosingContext(c.instr.Parent()) {
		return false
	}

	// Get package, if no information treat as empty package name
	pkgName := analysisutil.FindSafeCalleePkg(call.Common()).ValueOr("")
	var methodName string
	var receiverName string
	if call.Common().IsInvoke() {
		methodName = call.Common().Method.Name()
		receiverName = call.Common().Value.Type().String()
	} else {
		methodName = call.Common().Value.Name()
		receiverName = staticReceiver(call.Common())
	}

	allCalleesIds := calleeAliases(p, call)
	allCalleesIds = append(allCalleesIds,
		calleeInfo{method: methodName, pkg: pkgName, recv: receiverName})
	res := funcutil.Exists(allCalleesIds, func(cid calleeInfo) bool {
		if s.ReceiverType != nil && !s.ReceiverType.MatchString(cid.recv) {
			return false
		}
		return s.Package.MatchString(cid.pkg) &&
			s.Method.MatchString(cid.method)
	})
	return res
}

func staticReceiver(call *ssa.CallCommon) string {
	if call == nil {
		return ""
	}
	sig := call.Signature()
	if sig == nil {
		return ""
	}
	recv := sig.Recv()
	if recv == nil {
		return ""
	}
	return recv.Name()
}

// CallArgSpec is a specification for a call argument
type CallArgSpec struct {
	CommonSpec
	CallSpec
	Index    uint
	Name     *regexp.Regexp
	AnyIndex bool // AnyIndex indicates that index should be ignored and any arg matches
	Type     *regexp.Regexp
}

// MatchSsaCode matches call arguments when the call matches the call spec part of the spec and
// the argument has the same index and type specified in the CallArgSpec.
func (s CallArgSpec) MatchSsaCode(p *pointer.Result, c SsaCode) bool {
	if c.parent == nil {
		return false // a call arg is matching indirectly by looking at referrers
	}
	if c.value == nil {
		return false
	}

	callInstr, isCallInstr := c.parent.(ssa.CallInstruction)
	if !isCallInstr {
		return false
	}
	// To match a call argument, the call spec must at least match
	if !s.CallSpec.MatchSsaCode(p, NewInstrCode(callInstr)) {
		return false
	}
	// Find the argument that is equal to the value, and check if it matches
	args := lang.GetArgs(callInstr)
	params := lang.GetParams(callInstr)
	for i, arg := range args {
		if arg != c.value {
			continue
		}
		paramType := analysisutil.ParamTypStr(params[i], i, arg)
		paramName := params[i].Var.Name()
		if (s.Index == uint(i) || s.AnyIndex) &&
			s.Type.MatchString(paramType) &&
			s.Name.MatchString(paramName) {
			return true
		}
	}
	return false
}
