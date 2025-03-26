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

package summaries_test

import (
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

func TestParseSummariesFile(t *testing.T) {
	feSummaries, err := summaries.ParseSummariesFile("testdata/summaries.yaml")
	if err != nil {
		t.Error(err)
	}
	t.Logf("Summaries: %+v", feSummaries)
}

func TestParseSummariesInvalidFile(t *testing.T) {
	_, err := summaries.ParseSummariesFile("testdata/summaries-invalid.yaml")
	if err == nil {
		t.Error("Expected error")
	}
	// The user should receive meaningful error messages when receiving misconfiguration error messages.
	// If you need to change the error message, be aware.
	expectedSubstrs := []string{
		"package is empty",
		"interface IfaceNoMethod is set, but method is empty",
		"interface Iface and function FUNC are both set",
		"cannot parse \"x\"",
		"function FUNC and method METO are both set",
		"receiver Structe is set, but method is empty",
		"cannot parse \"!arg namesMustBeInAngles\" because \"namesMustBeInAngles\" is not an integer",
		"data cannot flow from a return node",
		"flow.From or flow.To contains !receiver, but not in a method's flow",
	}
	t.Logf("Error: %s", err)
	// Check that the error message contains all the substrings
	for _, substr := range expectedSubstrs {
		if !strings.Contains(err.Error(), substr) {
			t.Errorf("Expected error message to contain %q, but it did not, it's %s", substr, err)
		}
	}
}
