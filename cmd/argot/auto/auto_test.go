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

package auto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
)

func TestRunAutoSimple(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get wd: %s", err)
	}
	testdata := filepath.Join(wd, "testdata")
	cfg, err := tools.LoadConfig(tools.CommonFlags{ConfigPath: filepath.Join(testdata, "config.yaml")}, false)
	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}
	hasErr, report, err := runTarget(cfg, "main", config.TargetInfo{Files: []string{filepath.Join(testdata, "main.go")}}, Flags{
		CommonFlags: tools.CommonFlags{},
		maxDepth:    0,
		dryRun:      false,
	})
	if err != nil {
		t.Errorf("error running for main target: %s", err)
	}
	if !hasErr {
		t.Fatalf("expected to have findings")
	}
	t.Logf("Report: %+v", report)

	if len(report.Reports) != 3 {
		t.Fatalf("expected 3 reports, one for each of syntactic, taint and backtrace.")
	}
}
