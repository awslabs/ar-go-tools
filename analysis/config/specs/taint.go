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

// Taint is a taint analysis specification
type Taint struct {
	ParsedTaintSpec

	Sinks      []scanning.CodeSpec
	Sources    []scanning.CodeSpec
	Sanitizers []scanning.CodeSpec
	Validators []scanning.CodeSpec
	Filters    []scanning.CodeSpec
}

// NewTaintSpec returns a new Taint spec with the provided tag and empty definitions
func NewTaintSpec(tag string) Taint {
	return Taint{
		ParsedTaintSpec: ParsedTaintSpec{
			Tag: tag,
		},
		Sinks:      []scanning.CodeSpec{},
		Sources:    []scanning.CodeSpec{},
		Sanitizers: []scanning.CodeSpec{},
		Validators: []scanning.CodeSpec{},
		Filters:    []scanning.CodeSpec{},
	}
}

// Compile a parsed spec into an actual taint spec
func (ts ParsedTaintSpec) Compile() (Taint, error) {
	sources, err1 := compileCids(ts.Sources, false)
	sinks, err2 := compileCids(ts.Sinks, true)
	sanitizers, err3 := compileCids(ts.Sanitizers, true)
	validators, err4 := compileCids(ts.Validators, false)
	filters, err5 := compileCids(ts.Filters, true)

	err := errors.Join(err1, err2, err3, err4, err5)
	if err != nil {
		return Taint{}, err
	}

	return Taint{
		ParsedTaintSpec: ts,
		Sources:         sources,
		Sinks:           sinks,
		Sanitizers:      sanitizers,
		Validators:      validators,
		Filters:         filters,
	}, nil
}

// SpecTag returns the tag of the taint specification
func (ts ParsedTaintSpec) SpecTag() string {
	return ts.Tag
}

// SpecTargets returns the targets of the taint specification
func (ts ParsedTaintSpec) SpecTargets() []string {
	return ts.Targets
}

// SpecSeverity returns the severity of the taint specification
func (ts ParsedTaintSpec) SpecSeverity() analysiscfg.Severity {
	return ts.Severity
}

// IsSource returns true if the code identifier matches a source specification in the config file
func (ts Taint) IsSource(p *pointer.Result, code scanning.SsaCode) bool {
	return matchSsaCodeAnySpec(p, ts.Sources, code)
}

// IsSink returns true if the code identifier matches a sink in the config file
func (ts Taint) IsSink(p *pointer.Result, code scanning.SsaCode) bool {
	return matchSsaCodeAnySpec(p, ts.Sinks, code)
}

// IsSanitizer returns true if the code identifier matches a sanitizer in the config file
func (ts Taint) IsSanitizer(p *pointer.Result, code scanning.SsaCode) bool {
	return matchSsaCodeAnySpec(p, ts.Sanitizers, code)
}

// IsValidator returns true if the code identifier matches a validator  in the config file
func (ts Taint) IsValidator(p *pointer.Result, code scanning.SsaCode) bool {
	return matchSsaCodeAnySpec(p, ts.Validators, code)
}

// IsFiltered returns true if the ssa code matches any of the filters in the taint analysis problem
func (ts Taint) IsFiltered(p *pointer.Result, code scanning.SsaCode) bool {
	return matchSsaCodeAnySpec(p, ts.Filters, code)
}
