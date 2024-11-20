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

package tools

import "regexp"

// Captures errors happening before any analysis starts (program could not load)
var regexCouldNotLoad = regexp.MustCompile("could not load program")

// Captures the kind of error that happen when you put a flag at the end instead of go files
var namedFilesMustBeGoFiles = regexp.MustCompile("-: named files must be .go files: -(\\w)")

// Captures error in the analysis for steps that require a main program
var missingMainTestPackages = regexp.MustCompile("no main/test packages to analyze")

// Captures error where the config file references a reports directory that doesn't exist
var missingReportsDir = regexp.MustCompile("failed to set reports dir .* could not create directory")

// HintForErrorMessage looks for specific error message and returns some other message that might help the user
// resolve the problem.
func HintForErrorMessage(errMsg string) string {
	if regexCouldNotLoad.MatchString(errMsg) {
		if namedFilesMustBeGoFiles.MatchString(errMsg) {
			return "all command line flags should be before the path to the Go files to analyze"
		}
		return "make sure you have provided the right arguments for an analyzer to load a Go program"
	}
	if missingMainTestPackages.MatchString(errMsg) {
		return "this analysis analyzes executables with an entry point; the path should lead to a main package"
	}
	if missingReportsDir.MatchString(errMsg) {
		return "the reports directory referenced in the config file doesn't exist, you have to create it manually"
	}
	return ""
}
