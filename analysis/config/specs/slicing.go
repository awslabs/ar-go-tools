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

package specs

import (
	"errors"

	"github.com/awslabs/ar-go-tools/analysis/config/analysiscfg"
	"github.com/awslabs/ar-go-tools/analysis/scanning"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// Slicing is a compiled slicing spec
type Slicing struct {
	ParsedSlicingSpec

	BacktracePoints []scanning.CodeSpec

	Filters []scanning.CodeSpec
}

// NewSlicingSpec returns a Slicing spec with the provided tag
func NewSlicingSpec(tag string) Slicing {
	return Slicing{
		ParsedSlicingSpec: ParsedSlicingSpec{
			Tag: tag,
		},
		BacktracePoints: []scanning.CodeSpec{},
		Filters:         []scanning.CodeSpec{},
	}
}

// IsBacktracePoint returns true if the code is a backtrace point
func (s Slicing) IsBacktracePoint(p *pointer.Result, code scanning.SsaCode) bool {
	return matchSsaCodeAnySpec(p, s.BacktracePoints, code)
}

// IsFiltered returns true if the code is a filter
func (s Slicing) IsFiltered(p *pointer.Result, code scanning.SsaCode) bool {
	return matchSsaCodeAnySpec(p, s.Filters, code)
}

// SpecTag returns the tag of the slicing spec
func (ss ParsedSlicingSpec) SpecTag() string {
	return ss.Tag
}

// SpecTargets returns the targets of the slicing spec
func (ss ParsedSlicingSpec) SpecTargets() []string {
	return ss.Targets
}

// SpecSeverity returns the severity of the slicing spec
func (ss ParsedSlicingSpec) SpecSeverity() analysiscfg.Severity {
	return ss.Severity
}

// Compile a parsed spec into an actual taint spec
func (ss ParsedSlicingSpec) Compile() (Slicing, error) {
	backtracePts, err1 := compileCids(ss.BacktracePoints, true)
	filters, err2 := compileCids(ss.Filters, true)

	err := errors.Join(err1, err2)
	if err != nil {
		return Slicing{}, err
	}

	return Slicing{
		ParsedSlicingSpec: ss,
		BacktracePoints:   backtracePts,
		Filters:           filters,
	}, nil
}
