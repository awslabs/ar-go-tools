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
	"regexp"

	"github.com/awslabs/ar-go-tools/analysis/config/analysiscfg"
	funcs "github.com/awslabs/ar-go-tools/internal/funcutil"
)

// TargetsAll is the universal target
const TargetsAll = "all"

// ParsedDataflowProblems defines all the dataflow (taint, slicing) problems in a config file.
type ParsedDataflowProblems struct {
	// PathSensitiveFuncs is a list of regexes indicating which functions should be path-sensitive.
	// This allows the analysis to scale yet still maintain a degree of precision where it matters.
	PathSensitiveFuncs []string `xml:"field-sensitive-funcs" yaml:"field-sensitive-funcs" json:"field-sensitive-funcs"`

	// SummarizeOnDemand specifies whether the graph should build summaries on-demand instead of all at once
	SummarizeOnDemand bool `xml:"summarize-on-demand,attr" yaml:"summarize-on-demand" json:"summarize-on-demand"`

	// UserSpecs is a path to a json file that contains the data flows specs for the interfaces in the dataflow
	// analyses
	UserSpecs []string `yaml:"user-specs" json:"user-specs"`

	// TaintTrackingProblems lists the taint tracking specifications
	TaintTrackingProblems []ParsedTaintSpec `yaml:"taint-tracking" json:"taint-tracking"`

	// SlicingProblems lists the program slicing specifications
	SlicingProblems []ParsedSlicingSpec `yaml:"slicing" json:"slicing"`
}

// DataflowProblems defines all the dataflow (taint, slicing) problems in a config file.
type DataflowProblems struct {
	// PathSensitiveFuncsRegexes is a list of compiled regexes corresponding to PathSensitiveFuncs
	PathSensitiveFuncsRegexes []*regexp.Regexp

	// SummarizeOnDemand specifies whether the graph should build summaries on-demand instead of all at once
	SummarizeOnDemand bool

	// UserSpecs is a path to a json file that contains the data flows specs for the interfaces in the dataflow
	// analyses
	UserSpecs []string

	// TaintTrackingProblems lists the taint tracking specifications
	TaintTrackingProblems []Taint

	// SlicingProblems lists the program slicing specifications
	SlicingProblems []Slicing
}

// Compile the parsed dataflow problems into concrete dataflow problems
func (p ParsedDataflowProblems) Compile() (DataflowProblems, error) {
	// Compile all the parsed subproblems into their compiled form

	// Compile the taint analysis problems
	taintTrackingProblems := []Taint{}
	for _, tsp := range p.TaintTrackingProblems {
		t, err := tsp.Compile()
		if err != nil {
			return DataflowProblems{}, err
		}
		taintTrackingProblems = append(taintTrackingProblems, t)
	}

	// Compile the slicing problems
	slicingProblems := []Slicing{}
	for _, sp := range p.SlicingProblems {
		s, err := sp.Compile()
		if err != nil {
			return DataflowProblems{}, err
		}
		slicingProblems = append(slicingProblems, s)
	}

	d := DataflowProblems{
		SummarizeOnDemand:     p.SummarizeOnDemand,
		UserSpecs:             p.UserSpecs,
		TaintTrackingProblems: taintTrackingProblems,
		SlicingProblems:       slicingProblems,
	}
	if len(p.PathSensitiveFuncs) > 0 {
		psRegexes := make([]*regexp.Regexp, 0, len(p.PathSensitiveFuncs))
		for _, pf := range p.PathSensitiveFuncs {
			r, err := regexp.Compile(pf)
			if err != nil {
				continue
			}
			psRegexes = append(psRegexes, r)
		}
		d.PathSensitiveFuncsRegexes = psRegexes
	} else {
		d.PathSensitiveFuncsRegexes = []*regexp.Regexp{}
	}
	return d, nil
}

// ParsedTaintSpec contains code identifiers that identify a specific taint tracking problem, or contains a code that
// can differentiate groups of annotations
type ParsedTaintSpec struct {
	analysiscfg.ProblemCfg `xml:"override-analysis-options,attr" yaml:"override-analysis-options" json:"override-analysis-options"`
	// Sanitizers is the list of sanitizers for the taint analysis
	Sanitizers []ParsedCodeIdentifier

	// Validators is the list of validators for the dataflow analyses
	Validators []ParsedCodeIdentifier

	// Sinks is the list of sinks for the taint analysis
	Sinks []ParsedCodeIdentifier

	// Sources is the list of sources for the taint analysis
	Sources []ParsedCodeIdentifier

	// Filters contains a list of filters that can be used by analyses
	Filters []ParsedCodeIdentifier

	// Tag identifies a group of annotations when used with annotations
	Tag string

	// Severity assigns a severity to this problem
	Severity analysiscfg.Severity

	// Description allows the user to add a description to the problem
	Description string

	// Targets identifies the names of the targets this analysis must run against
	Targets []string

	// FailOnImplicitFlow indicates whether the taint analysis should fail when tainted data implicitly changes
	// the control flow of a program. This should be set to false when proving a data flow property,
	// and set to true when proving an information flow property.
	FailOnImplicitFlow bool `yaml:"fail-on-implicit-flow" json:"fail-on-implicit-flow"`

	// SkipBoundLabels indicates whether to skip flows that go through "bound labels", i.e. aliases of the variables
	// bound by a closure. This can be useful to test data flows because bound labels generate a lot of false positives.
	SkipBoundLabels bool `yaml:"unsafe-skip-bound-labels" json:"unsafe-skip-bound-labels"`

	// SourceTaintsArgs specifies whether calls to a source function also taints the argument. This is usually not
	// the case, but might be useful for some users or for source functions that do not return anything.
	SourceTaintsArgs bool `xml:"source-taints-args,attr" yaml:"source-taints-args" json:"source-taints-args"`
}

// ParsedSlicingSpec contains code identifiers that identify a specific program slicing / backwards
// dataflow analysis spec.
type ParsedSlicingSpec struct {
	analysiscfg.ProblemCfg `xml:"override-analysis-options,attr" yaml:"override-analysis-options" json:"override-analysis-options"`
	// BacktracePoints is the list of identifiers to be considered as entrypoint functions for the backwards
	// dataflow analysis.
	BacktracePoints []ParsedCodeIdentifier

	// Filters contains a list of filters that can be used by analyses
	Filters []ParsedCodeIdentifier

	// Tag identifies a group of annotations when used with annotations
	Tag string

	// Severity assigns a severity to this problem
	Severity analysiscfg.Severity

	// Description allows the user to add a description to the problem
	Description string

	// Targets identifies the names of the targets this analysis must run against
	Targets []string

	// MustBeStatic set to true indicates that all the data flowing to backtrace points must be static (constants,
	// static string)
	MustBeStatic bool `yaml:"must-be-static" json:"must-be-static"`

	// SkipBoundLabels indicates whether to skip flows that go through "bound labels", i.e. aliases of the variables
	// bound by a closure. This can be useful to test data flows because bound labels generate a lot of false positives.
	SkipBoundLabels bool `yaml:"unsafe-skip-bound-labels" json:"unsafe-skip-bound-labels"`
}

// StaticCommandsSpec contains code identifiers for the problem of identifying which commands are static
type StaticCommandsSpec struct {
	// StaticCommands is the list of identifiers to be considered as command execution for the static commands analysis
	// (not used)
	StaticCommands []ParsedCodeIdentifier `yaml:"static-commands" json:"static-commands"`
}

// SyntacticSpecs contains specs for the different syntactic analysis problems.
type SyntacticSpecs struct {
	// StructInitSpecs is the list of specs for the struct inititialization problems.
	StructInitProblems []StructInitSpec `yaml:"struct-inits" json:"struct-inits"`

	// CondCheckSpecs is the list of specs for the condition checking problems.
	CondCheckSpecs []CondCheckSpec `yaml:"cond-checks" json:"cond-checks"`
}

// StructInitSpec contains specs for the problem of tracking a specific struct initialization.
type StructInitSpec struct {
	// Tag is the identifier of the problem
	Tag string
	// Severity is the severity of the finding when some struct is not initialized properly
	Severity analysiscfg.Severity
	// Description is a human-readable description of the problem
	Description string
	Targets     []string
	// Struct is the struct type whose initialization should be tracked.
	Struct ParsedCodeIdentifier
	// FieldsSet is the list of the fields of Struct that must always be set to a specific value.
	FieldsSet []FieldsSetSpec `yaml:"fields-set" json:"fields-set"`
	// Filters is the list of values that the analysis does not track.
	Filters []ParsedCodeIdentifier
	// MustReinits is the list of function calls resulting in the struct that must be
	// folllowed by a statement reinitializing the struct value
	MustReinits []ParsedCodeIdentifier `yaml:"must-reinit" json:"must-reinit"`
}

// SpecTag returns the struct init specification's tag
func (si StructInitSpec) SpecTag() string {
	return si.Tag
}

// SpecTargets returns the struct init specification's targets
func (si StructInitSpec) SpecTargets() []string {
	return si.Targets
}

// SpecSeverity returns the struct init specification's severity
func (si StructInitSpec) SpecSeverity() analysiscfg.Severity {
	return si.Severity
}

// FieldsSetSpec contains the code identifiers for the problem of tracking how a
// struct's fields are initialized.
type FieldsSetSpec struct {
	// Field is the struct field name whose value must be initialized to the Value.
	Field string
	// Value is the value that Field must always be set to.
	// We only support static values for now (e.g., constants and static functions).
	Value ParsedCodeIdentifier
}

// CondCheckSpec is a specification for the precondition analysis. On top of the common fields (Tag, Severity,
// Description and Targets) it specifies a Call (the call that needs to ge guarded by a precondition) and the
// Preconditions.
type CondCheckSpec struct {
	// Tag is the identifier of the problem
	Tag string
	// Severity is the severity of the finding when some struct is not initialized properly
	Severity analysiscfg.Severity
	// Description is a human-readable description of the problem
	Description string
	// Targets of this problem
	Targets []string
	// Call is the calls that need to be guarded
	Call []ParsedCodeIdentifier
	// Preconditions is the list of conditions that need to be satisfied before making a Call.
	// The Call is valid if one of the preconditions is valid on all control-flow paths to the Call.
	Preconditions []GuardSpec
}

// SpecTag returns the precondition check specification's tag
func (cc CondCheckSpec) SpecTag() string {
	return cc.Tag
}

// SpecTargets returns the precondition check specification's targets
func (cc CondCheckSpec) SpecTargets() []string {
	return cc.Targets
}

// SpecSeverity returns the precondition check specification's severity
func (cc CondCheckSpec) SpecSeverity() analysiscfg.Severity {
	return cc.Severity
}

// GuardSpec is the specification of a guard or condition
// Currently, it only contains a Precondition which is a list of string represented conjuncts. This
// makes it at little difficult to specify in a config file, so we will make a more extensible and
// precise GuardSpec in the future.
type GuardSpec struct {
	// Precondition is the function that is used in the condition
	Precondition []string
}

// A TargetSpec is a set of files the form a Go program together with a name to identify the target
// in the configuration file.
type TargetSpec struct {
	// Name identifies the target in the rest of the configuration file
	Name string
	// Files identifies the target's files
	Files []string
	// Platform identifies the target's platform
	Platform string

	// UseProgramTransforms indicates that the tool should apply program transformations before
	// running any analysis. Program transformations can be expensive to apply, but they can
	// eliminate sources of imprecision and sources of unsoundness.
	// NOTE: this option may change to let the user choose precisely which program transformations
	// to apply
	UseProgramTransforms bool `xml:"use-program-transforms" yaml:"use-program-transforms" json:"use-program-transforms"`

	// ReflectValueCallInstances lists functions that take as argument a class. The program will be
	// transformed to rewrite (reflect.Value).Call instances that can be statically resolved to the
	// class's method.
	ReflectValueCallInstances []ParsedCodeIdentifier `xml:"reflect-value-call-instances" yaml:"reflect-value-call-instances" json:"reflect-value-call-instances"`
}

// IsStaticCommand returns true if the code identifier matches a static command specification in
// the config file
func (scs StaticCommandsSpec) IsStaticCommand(cid ParsedCodeIdentifier) bool {
	return ExistsCid(scs.StaticCommands, cid.EqualOnNonEmptyFields)
}

// IsBacktracePoint returns true if the code identifier matches a backtrace point according to the
// SlicingSpec
func (ss ParsedSlicingSpec) IsBacktracePoint(cid ParsedCodeIdentifier) (ParsedCodeIdentifier, bool) {
	if ExistsCid(ss.BacktracePoints, cid.EqualOnNonEmptyFields) {
		return cid, true
	}

	return ParsedCodeIdentifier{}, false
}

// TargetIncludes returns true if the list of targets includes the targets or has the "all" target,
// or the target is empty (the program is passed through the command line)
func TargetIncludes(targets []string, sub string) bool {
	return sub == "" || funcs.Contains(targets, TargetsAll) || funcs.Contains(targets, sub)
}
