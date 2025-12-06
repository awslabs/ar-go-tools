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
	"fmt"
	"path/filepath"
	"slices"
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

func TestInferCalleeSummaries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	tests := []struct {
		fn   summaries.FrontendDataflowSummary
		want map[string][]summaries.DetailedSummary
		via  Method
	}{
		{
			fn: summaries.NewFunctionFlowSummary(
				"github.com/awslabs/ar-go-tools/analysis/check/testdata/genspec",
				"threeArgInter",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 1}: {
							summaries.ArgumentSNode{Name: "b", Index: 2},
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "b", Index: 2}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"add2": {
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "a", Index: 0}: {
								summaries.ArgumentSNode{Name: "b", Index: 1},
							},
							summaries.ArgumentSNode{Name: "b", Index: 1}: {
								summaries.ArgumentSNode{Name: "a", Index: 0},
							},
							summaries.ArgumentSNode{Name: "no", Index: 2}: {
								summaries.ArgumentSNode{Name: "a", Index: 0},
								summaries.ArgumentSNode{Name: "b", Index: 1},
							},
						},
					},
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "a", Index: 0}: {
								summaries.ArgumentSNode{Name: "b", Index: 1},
								summaries.ReturnSNode{Index: 0},
							},
							summaries.ArgumentSNode{Name: "b", Index: 1}: {
								summaries.ArgumentSNode{Name: "a", Index: 0},
								summaries.ReturnSNode{Index: 0},
							},
						},
					},
				},
			},
			via: General,
		},
		{
			fn: summaries.NewFunctionFlowSummary(
				"github.com/awslabs/ar-go-tools/analysis/check/testdata/genspec",
				"threeArgInter",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 1}: {
							summaries.ArgumentSNode{Name: "b", Index: 2},
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "b", Index: 2}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"add2": {
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "a", Index: 0}: {
								summaries.ReturnSNode{Index: 0},
							},
							summaries.ArgumentSNode{Name: "b", Index: 1}: {
								summaries.ReturnSNode{Index: 0},
							},
						},
					},
				},
			},
			via: Types,
		},
		{
			fn: summaries.NewFunctionFlowSummary(
				"github.com/awslabs/ar-go-tools/analysis/check/testdata/genspec",
				"threeArgInterDiffCallees",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 1}: {
							summaries.ArgumentSNode{Name: "b", Index: 2},
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "b", Index: 2}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"add1": {
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "a", Index: 0}: {
								summaries.ReturnSNode{Index: 0},
							},
							summaries.ArgumentSNode{Name: "b", Index: 1}: {
								summaries.ReturnSNode{Index: 0},
							},
						},
					},
				},
				"add2": {
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "a", Index: 0}: {
								summaries.ReturnSNode{Index: 0},
							},
							summaries.ArgumentSNode{Name: "b", Index: 1}: {
								summaries.ReturnSNode{Index: 0},
							},
						},
					},
				},
			},
			via: Types,
		},
		{
			// NOTE This summary is deliberately incorrect:
			// If src cannot flow to dst, then no parameter of helper can flow to helper's return
			fn: summaries.NewFunctionFlowSummary(
				"github.com/awslabs/ar-go-tools/analysis/check/testdata/genspec",
				"fieldPropagation",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "dst", Index: 1}: {
							summaries.ArgumentSNode{Name: "src", Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"helper": {
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "a", Index: 0}: {
								summaries.ArgumentSNode{Name: "b", Index: 1},
							},
							summaries.ArgumentSNode{Name: "b", Index: 1}: {
								summaries.ArgumentSNode{Name: "a", Index: 0},
							},
						},
					},
				},
			},
			via: Types,
		},
		{
			fn: summaries.NewFunctionFlowSummary(
				"github.com/awslabs/ar-go-tools/analysis/check/testdata/genspec",
				"sharedMutation",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 0}: {
							summaries.ArgumentSNode{Name: "shared", Index: 2},
						},
						summaries.ArgumentSNode{Name: "b", Index: 1}: {
							summaries.ArgumentSNode{Name: "shared", Index: 2},
						},
						summaries.ArgumentSNode{Name: "shared", Index: 2}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"modify": {
					{
						// The empty summary is the only valid summary for `modify` given this summary because:
						// - a and b cannot flow to ret, meaning that val cannot flow to s
						// - shared cannot flow to a or b, meaning that s cannot flow to val
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
					},
				},
			},
			via: Types,
		},
		{
			fn: summaries.NewFunctionFlowSummary(
				"github.com/awslabs/ar-go-tools/analysis/check/testdata/genspec",
				"sharedMutation",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 0}: {
							summaries.ArgumentSNode{Name: "shared", Index: 2},
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "b", Index: 1}: {
							summaries.ArgumentSNode{Name: "shared", Index: 2},
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "shared", Index: 2}: {
							summaries.ArgumentSNode{Name: "a", Index: 0},
							summaries.ArgumentSNode{Name: "b", Index: 1},
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"modify": {
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "val", Index: 0}: {
								summaries.ArgumentSNode{Name: "s", Index: 1},
							},
						},
					},
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.ArgumentSNode{Name: "s", Index: 1}: {
								summaries.ArgumentSNode{Name: "val", Index: 0},
							},
						},
					},
				},
			},
			via: Types,
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s via %s", tc.fn.Name(), tc.via), func(t *testing.T) {
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
			f, err := functionOfSummary(state, tc.fn)
			if err != nil {
				t.Fatalf("failed to find function for summary %v", tc.fn.Name())
			}
			g, ok := state.FlowGraph.Summaries[f]
			if !ok {
				t.Fatalf("no summary for function %s", f)
			}
			if !g.Constructed {
				dataflow.RunIntraProcedural(context.Background(), state, g)
			}
			summs, err := inferCalleeSummaries(state, g, tc.fn.Summary(), tc.via)
			if err != nil {
				t.Fatal(err)
			}
			if len(summs) == 0 {
				t.Fatalf("no summaries inferred for function %s via %s", tc.fn.Name(), tc.via)
			}

			for calleeG, inferredSummaries := range summs {
				calleeName := calleeG.Parent.Name()
				wantSummaries, ok := tc.want[calleeName]
				if !ok {
					t.Errorf("callee not in tc.want: %v", calleeName)
					continue
				}

				// Check exact match: same number of summaries
				if len(inferredSummaries) != len(wantSummaries) {
					t.Errorf("number of summaries mismatch for %s: want %d, got %d",
						calleeName, len(wantSummaries), len(inferredSummaries))
					t.Logf("want summaries:")
					for i, ws := range wantSummaries {
						t.Logf("  [%d]: %+v", i, ws)
					}
					t.Logf("got summaries:")
					for i, gs := range inferredSummaries {
						t.Logf("  [%d]: %+v", i, gs)
					}
					continue
				}

				// For each expected summary, check that exactly one inferred summary matches it
				matchedInferred := make(map[int]bool)
				for j, wantSumm := range wantSummaries {
					foundMatch := false

					for i, inferredSumm := range inferredSummaries {
						if matchedInferred[i] {
							continue // Already matched to another expected summary
						}

						got := inferredSumm
						if len(got.Flows) != len(wantSumm.Flows) {
							continue
						}

						allFlowsMatch := true
						for gfrom, gtos := range got.Flows {
							wtos, ok := wantSumm.Flows[gfrom]
							if !ok {
								allFlowsMatch = false
								break
							}
							if len(gtos) != len(wtos) {
								allFlowsMatch = false
								break
							}
							for _, wto := range wtos {
								if !slices.Contains(gtos, wto) {
									allFlowsMatch = false
									break
								}
							}
							if !allFlowsMatch {
								break
							}
						}

						if allFlowsMatch {
							foundMatch = true
							matchedInferred[i] = true
							break
						}
					}

					if !foundMatch {
						t.Errorf("expected summary [%d] for %s not found in inferred summaries", j, calleeName)
						t.Logf("want: %+v", wantSumm)
						t.Logf("got summaries:")
						for i, gs := range inferredSummaries {
							t.Logf("  [%d]: %+v", i, gs)
						}
					}
				}
			}
		})
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
