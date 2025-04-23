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
	"go/token"
	"regexp"

	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// ChannelRecvSpec specifies a code location where data is read from a channel with values
// of a certain type.
type ChannelRecvSpec struct {
	CommonSpec
	Type       *regexp.Regexp
	ValueMatch *regexp.Regexp
}

// MatchAstCode matches ast elements
func (s ChannelRecvSpec) MatchAstCode(a AstCode) bool { panic("UNIMPLEMENTED") }

// MatchSsaCode returns true when the value is a channel read that matches the spec
func (s ChannelRecvSpec) MatchSsaCode(p *pointer.Result, c SsaCode) bool {
	if c.instr == nil {
		return false
	}
	if !s.matchEnclosingContext(c.instr.Parent()) {
		return false
	}
	if node, isUnop := c.instr.(*ssa.UnOp); isUnop {
		// check this is a "<- c"
		if node.Op != token.ARROW {
			return false
		}
		packageName, typeName, err := analysisutil.FindEltTypePackage(node.X.Type(), "%s")
		if err != nil {
			return false
		}
		res := s.Package.MatchString(packageName) &&
			s.Type.MatchString(typeName) &&
			s.ValueMatch.MatchString(node.String())
		return res
	}
	return false
}
