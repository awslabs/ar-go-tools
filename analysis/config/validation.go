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

package config

import (
	"fmt"

	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// Validate validates the config and returns an error if there is some invalid setting
func (c Config) Validate() error {
	if err := c.checkTagsAreUnique(); err != nil {
		return err
	}
	if err := c.checkSeveritiesAreValid(); err != nil {
		return err
	}
	if err := c.checkTargetsUniqueAndDefined(); err != nil {
		return err
	}
	return nil
}

func (c Config) checkTagsAreUnique() error {
	hasUnsetTag := false
	tags := map[string]bool{}
	tagsList := funcutil.Map(c.TaintTrackingProblems, func(ts TaintSpec) string { return ts.Tag })
	tagsList = append(tagsList, funcutil.Map(c.SlicingProblems, func(ts SlicingSpec) string { return ts.Tag })...)
	for _, tag := range tagsList {
		if tag == "" {
			if hasUnsetTag {
				return fmt.Errorf("there can be only one problem with an unspecified tag")
			}
			hasUnsetTag = true
		} else if tags[tag] {
			return fmt.Errorf("tag %s is used for multiple problems", tag)
		}
		tags[tag] = true
	}
	return nil
}

func (c Config) checkSeveritiesAreValid() error {
	sevList := funcutil.Map(c.TaintTrackingProblems, func(ts TaintSpec) string { return ts.Severity })
	sevList = append(sevList, funcutil.Map(c.SlicingProblems, func(ts SlicingSpec) string { return ts.Severity })...)
	for _, sev := range sevList {
		if !isValidSeverity(sev) {
			return fmt.Errorf(
				"invalid severity label %s (not empty, \"CRITICAL\", \"HIGH\", \"MEDIUM\", or \"LOW\")",
				sev)
		}
	}
	return nil
}

func (c Config) checkTargetsUniqueAndDefined() error {
	targets := funcutil.Set(funcutil.Map(c.Targets, func(c TargetSpec) string { return c.Name }))
	if len(targets) != len(c.Targets) {
		return fmt.Errorf("duplicate target names")
	}
	isDefined := func(s string) bool {
		_, ok := targets[s]
		return ok || s == TargetsAll
	}
	for _, trackingProblem := range c.TaintTrackingProblems {
		for _, problemTarget := range trackingProblem.Targets {
			if !isDefined(problemTarget) {
				return fmt.Errorf("taint analysis target %s is undefined", problemTarget)
			}
		}
	}
	for _, slicingProblem := range c.SlicingProblems {
		for _, problemTarget := range slicingProblem.Targets {
			if !isDefined(problemTarget) {
				return fmt.Errorf("backwards dataflow analysis target %s is undefined", problemTarget)
			}
		}
	}
	for _, sp := range c.SyntacticProblems {
		for _, structInitProblem := range sp.StructInitProblems {
			for _, problemTarget := range structInitProblem.Targets {
				if !isDefined(problemTarget) {
					return fmt.Errorf("syntactic analysis target %s is undefined", problemTarget)
				}
			}
		}
	}
	return nil
}

func isValidSeverity(s string) bool {
	switch s {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return true
	default:
		return false
	}
}
