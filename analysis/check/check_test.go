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

package check_test

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/check"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

//go:embed testdata
var testfsys embed.FS

func TestCheckSummary_BasicFunctions(t *testing.T) {
	dir := filepath.Join("./testdata", "basic")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp, false)
	state, err := result.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	check.InitializeState(state)

	tests := []struct {
		name string
		via  check.Method
		want []string
	}{
		{
			name: "singleArgIntraOut",
			via:  check.Naive,
			want: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			str := fmt.Sprintf(`
{
	"package": "github.com/awslabs/ar-go-tools/analysis/check/testdata/basic",
	"function": "%s",
	"flows": [%s]
}`, tc.name, strings.Join(tc.want, ", "))
			var summary summaries.FunctionFlowSummary
			if err := summary.UnmarshalJSON([]byte(str)); err != nil {
				t.Fatalf("failed to unmarshal summary %s: %v", str, err)
			}
			res, err := check.CheckSummary(state, summary, tc.via)
			if err != nil {
				t.Errorf("failed to check summary for %s: %v\n", summary.Name(), err)
			}
			t.Logf("%s\n", res.Got)
		})
	}
}

func setupConfig(lp *loadprogram.State, summarizeOnDemand bool) {
	level := config.ErrLevel // change this as needed for debugging
	lp.Logger.Level = level

	cfg := lp.Config
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false // change this as needed for debugging
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(level)
	cfg.SummarizeOnDemand = summarizeOnDemand
}
