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

import (
	"strings"
	"testing"
)

func validateHint(t *testing.T, errorMsg string, containedHint string) {
	hint := HintForErrorMessage(errorMsg)
	if !strings.Contains(hint, containedHint) {
		t.Fatalf("incorrect hint; check and update error message if necessary")
	}
}

func TestHintForFlagAfterFiles(t *testing.T) {
	errorMsg := "error: could not load program:\n -: named files must be .go files: -v"
	containedHint := "all command line flags should be before the path"
	validateHint(t, errorMsg, containedHint)
}

func TestHintForFailedLoadProgram(t *testing.T) {
	errorMsg := "error: could not load program:\n errors found, exiting\n"
	containedHint := "you have provided the right arguments for an analyzer to load a Go program"
	validateHint(t, errorMsg, containedHint)
}

func TestHintForMissingMain(t *testing.T) {
	errorMsg := "error: taint analysis failed: error while running parallel steps:" +
		" failed to build analyzer state: no main/test packages to analyze (check $GOROOT/$GOPATH)\n"
	containedHint := "this analysis analyzes executables with an entry point; the path should lead to a main package"
	validateHint(t, errorMsg, containedHint)
}
