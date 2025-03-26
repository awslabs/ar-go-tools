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
	"os"

	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// A list of supported Platforms. We may want to figure out how to get it programmatically, but this should suffice
// for now.
// A list of platforms can be found in src/go/build/syslist.go in your go installation source.
// Alternatively, run go tool dist list, the output shows 'platforms/architecture' supported by go.
var supportedPlatforms = []string{"linux", "darwin", "windows", "android", "ios", "freebsd", "netbsd", "openbsd"}

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
	if err := c.checkTargetOsesAreValid(); err != nil {
		return err
	}
	if err := c.checkUserSpecsAreValid(); err != nil {
		return err
	}
	return nil
}

func (c Config) checkTagsAreUnique() error {
	hasUnsetTag := false
	tags := map[string]bool{}
	tagsList := funcutil.Map(c.GetSpecs(), func(tg TaggedSpec) string { return tg.SpecTag() })
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
	for _, taggedSpec := range c.GetSpecs() {
		if !IsValidSeverityStr(taggedSpec.SpecSeverity().String()) {
			return fmt.Errorf(
				"invalid severity label %s (not empty, \"CRITICAL\", \"HIGH\", \"MEDIUM\", or \"LOW\")",
				taggedSpec.SpecSeverity())
		}
	}
	return nil
}

func (c Config) checkTargetOsesAreValid() error {
	for _, target := range c.Targets {
		if target.Platform != "" && !funcutil.Contains(supportedPlatforms, target.Platform) {
			return fmt.Errorf("platform %q in target %q is not supported", target.Platform, target.Name)
		}
	}
	return nil
}

func (c Config) checkTargetsUniqueAndDefined() error {
	targets := funcutil.Set(funcutil.Map(c.Targets, func(c TargetSpec) string { return c.Name }))
	if _, hasEmptyTargetName := targets[""]; hasEmptyTargetName {
		return fmt.Errorf("target names must be non empty")
	}
	if len(targets) != len(c.Targets) {
		return fmt.Errorf("duplicate target names")
	}
	isDefined := func(s string) bool {
		_, ok := targets[s]
		return ok || s == TargetsAll
	}
	for _, taggedSpec := range c.GetSpecs() {
		for _, problemTarget := range taggedSpec.SpecTargets() {
			if !isDefined(problemTarget) {
				return fmt.Errorf("target \"%s\" for problem with tag %q is undefined", problemTarget,
					taggedSpec.SpecTag())
			}
		}
	}
	return nil
}

func (c Config) checkUserSpecsAreValid() error {
	for _, specFileName := range c.DataflowProblems.UserSpecs {
		// test if specFileName exists
		if _, err := os.Stat(c.RelPath(specFileName)); err != nil {
			return fmt.Errorf("user spec file %q in dataflow-problems.user-specs does not exist", specFileName)
		}
	}
	return nil
}
