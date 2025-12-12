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
	pkg := "github.com/awslabs/ar-go-tools/analysis/check/testdata/basic"
	tests := []struct {
		fn   summaries.FrontendDataflowSummary
		want map[string][]summaries.DetailedSummary
		via  Method
	}{
		{
			fn: summaries.NewFunctionFlowSummary(pkg, "threeArgInter",
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
			fn: summaries.NewFunctionFlowSummary(pkg, "threeArgInter",
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
			fn: summaries.NewFunctionFlowSummary(pkg, "threeArgInterDiffCallees",
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
			// If src cannot flow to dst, then no parameter of addVals can flow to its return
			fn: summaries.NewFunctionFlowSummary(pkg, "propagateFields",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "dst", Index: 1}: {
							summaries.ArgumentSNode{Name: "src", Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"addVals": {
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
			fn: summaries.NewFunctionFlowSummary(pkg, "sharedMutation",
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
						// The empty summary is the only valid summary for `modify` given this
						// summary because:
						// - a and b cannot flow to ret, meaning that val cannot flow to s
						// - shared cannot flow to a or b, meaning that s cannot flow to val
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
					},
				},
			},
			via: Types,
		},
		{
			fn: summaries.NewFunctionFlowSummary(pkg, "sharedMutation",
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
		{
			fn: summaries.NewFunctionFlowSummary(pkg, "writeToClosed",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"writeToClosed$1": {
					{
						// Without the types analysis, we cannot prove that param y must not flow to
						// param x in writeToClosed, which means the closure's summary must satisfy
						// this constraint. This means that free variable y cannot flow to free
						// variable x or the closure's return.
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.FreeVarSNode{Name: "x"}: {
								summaries.ReturnSNode{Index: 0},
							},
						},
					},
				},
			},
			via: General,
		},
		{
			fn: summaries.NewFunctionFlowSummary(pkg, "writeToClosed",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: map[string][]summaries.DetailedSummary{
				"writeToClosed$1": {
					{
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.FreeVarSNode{Name: "x"}: {
								summaries.FreeVarSNode{Name: "y"},
								summaries.ReturnSNode{Index: 0},
							},
						},
					},
					{
						// NOTE This second inferred summary is fine because it does not include a
						// flow from x to the closure's return, which means y cannot flow to the
						// return.
						Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
							summaries.FreeVarSNode{Name: "x"}: {
								summaries.FreeVarSNode{Name: "y"},
							},
							summaries.FreeVarSNode{Name: "y"}: {
								summaries.FreeVarSNode{Name: "x"},
							},
						},
					},
				},
			},
			via: Types,
		},
	}

	dir := filepath.Join("./testdata", "basic")
	lp, err := analysistest.LoadTest(
		testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	state, err := result.Bind(result.Bind(ptr.NewState(lp), dataflow.NewState), NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s via %s", tc.fn.Name(), tc.via), func(t *testing.T) {
			f, err := functionOfName(state, tc.fn.Name())
			if err != nil {
				t.Fatalf("failed to find function for summary %v", tc.fn.Name())
			}
			g := dataflow.NewSummaryGraph(state.State, f, dataflow.GetUniqueFunctionID(), nil, nil)
			state.FlowGraph.Summaries[f] = g
			ctx := context.Background()
			if _, err := dataflow.RunIntraProcedural(ctx, state.State, g); err != nil {
				t.Fatal(err)
			}

			res := checkSummaryMostGeneral(g, tc.fn.Summary())
			if tc.via == Types {
				res = checkSummaryTypes(res.mustNotFlows)
			}
			state.Logger.Tracef("must-not-flows for function %s: %v\n", g.Parent, res.mustNotFlows)
			summs, err := inferCalleeSummaries(ctx, state.State, g, res.mustNotFlows, tc.via)
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
						t.Errorf(
							"expected summary [%d] for %s not found in inferred summaries",
							j, calleeName)
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
