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

package check

import (
	"context"
	"embed"
	"path/filepath"
	"testing"

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

func TestFindSubspecs(t *testing.T) {
	dir := filepath.Join("./testdata", "genspec")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	state, err := result.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	InitializeState(state)

	str := `
{
	"package": "github.com/awslabs/ar-go-tools/analysis/check/testdata/genspec",
	"function": "threeArgInter",
	"flows": [
		{"from": "!arg <a>", "to": "!arg <b>"},
		{"from": "!arg <a>", "to": "!ret"},
		{"from": "!arg <b>", "to": "!ret"}
	]
}`
	var wantSummary summaries.FunctionFlowSummary
	if err := wantSummary.UnmarshalJSON([]byte(str)); err != nil {
		t.Fatalf("failed to unmarshal summary %s: %v", str, err)
	}
	f, err := functionOfSummary(state, wantSummary)
	if err != nil {
		t.Fatalf("failed to find function for summary %v", wantSummary)
	}
	g, ok := state.FlowGraph.Summaries[f]
	if !ok {
		t.Fatalf("no summary for function %s", f)
	}
	if !g.Constructed {
		dataflow.RunIntraProcedural(context.Background(), state, g)
	}
	mustNotFlowEdges := findSubspecs(state, g, wantSummary)
	t.Log(mustNotFlowEdges)
	if len(mustNotFlowEdges) != 3 {
		t.Error("want 3 must not flow edges (TODO actually check edges)")
	}
}

func setupConfig(lp *loadprogram.State) {
	level := config.ErrLevel // change this as needed for debugging
	lp.Logger.Level = level

	cfg := lp.Config
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false // change this as needed for debugging
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(level)
}
