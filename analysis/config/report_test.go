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
	"testing"

	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

func TestMerge(t *testing.T) {
	report1 := NewReport()
	report2 := NewReport()
	report1.addEntry("tag1", ReportEntry{
		Tool:        SyntacticTool,
		ContentFile: "example.json",
		Severity:    High,
	})
	report2.addEntry("tag1", ReportEntry{
		Tool:        SyntacticTool,
		ContentFile: "ex2.json",
		Severity:    High,
	})
	report2.addEntry("tag2", ReportEntry{
		Tool:        SyntacticTool,
		ContentFile: "example3.json",
		Severity:    Low,
	})
	report1.Merge(report2)
	if !funcutil.Contains(report1.Reports["tag1"].Details, "ex2.json") {
		t.Fatalf("report1 should contain report2's ex2.json file after merge in tag1")
	}
}
