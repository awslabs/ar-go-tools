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
	"context"
	"embed"
	"fmt"
	"path/filepath"
	"slices"
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

func TestCheckSummary_Basic(t *testing.T) {
	dir := filepath.Join("./testdata", "basic")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	state, err := result.Bind(result.Bind(ptr.NewState(lp), dataflow.NewState), check.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}

	pkg := "github.com/awslabs/ar-go-tools/analysis/check/testdata/basic"
	tests := []tcCheck{
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "singleArgIntraOut",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: []check.Flow{},
				Method:   check.General,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "singleArgInterNone",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: []check.Flow{
					// NOTE Immutability analysis disproved these flows
					// {
					// 	Fn:   pkg + ".singleArgInterNone",
					// 	From: summaries.ArgumentSNode{Name: "x", Index: 0},
					// 	To:   summaries.ReturnSNode{Index: 0},
					// },
					// {
					// 	Fn:   pkg + ".noop",
					// 	From: summaries.ArgumentSNode{Name: "arg0", Index: 0},
					// 	To:   summaries.ReturnSNode{Index: 0},
					// },
				},
				Method: check.Immutability,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "twoArgIntraInout",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "y", Index: 1},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound: false,
				BadFlows: []check.Flow{
					{
						Fn:   pkg + ".twoArgIntraInout",
						From: summaries.ArgumentSNode{Name: "y", Index: 1},
						To:   summaries.ArgumentSNode{Name: "x", Index: 0},
					},
				},
				Method: check.Types,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "twoArgInterInout",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "y", Index: 1},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: nil,
				Method:   check.Types, // disproved flow from setmem dst -> src
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "singleArgIntraGlobal",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true, // TODO global analysis
				BadFlows: nil,
				Method:   check.General,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "singleArgInterGlobal",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true, // TODO global analysis
				BadFlows: nil,
				Method:   check.General,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "twoArgInterBool",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: nil,
				Method:   check.Types,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "twoArgInter",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: nil,
				Method:   check.Types,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "threeArgInter",
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
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: []check.Flow{
					// NOTE Immutability analysis disproved these flows
					// {
					// 	Fn:   pkg + ".threeArgInter",
					// 	From: summaries.ArgumentSNode{Name: "no", Index: 0},
					// 	To:   summaries.ReturnSNode{Index: 0},
					// },
					// {
					// 	Fn:   pkg + ".threeArgInter",
					// 	From: summaries.ArgumentSNode{Name: "no", Index: 0},
					// 	To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					// },
					// {
					// 	Fn:   pkg + ".threeArgInter",
					// 	From: summaries.ArgumentSNode{Name: "no", Index: 0},
					// 	To:   summaries.ArgumentSNode{Name: "b", Index: 2},
					// },
					// {
					// 	Fn:   pkg + ".threeArgInter",
					// 	From: summaries.ArgumentSNode{Name: "a", Index: 1},
					// 	To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					// },
					// {
					// 	Fn:   pkg + ".threeArgInter",
					// 	From: summaries.ArgumentSNode{Name: "b", Index: 2},
					// 	To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					// },
					// {
					// 	Fn:   pkg + ".threeArgInter",
					// 	From: summaries.ArgumentSNode{Name: "b", Index: 2},
					// 	To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					// },
					// {
					// 	Fn:   pkg + ".add2",
					// 	From: summaries.ArgumentSNode{Name: "no", Index: 2},
					// 	To:   summaries.ReturnSNode{Index: 0},
					// },
					// {
					// 	Fn:   pkg + ".add2",
					// 	From: summaries.ArgumentSNode{Name: "a", Index: 0},
					// 	To:   summaries.ArgumentSNode{Name: "no", Index: 2},
					// },
					// {
					// 	Fn:   pkg + ".add2",
					// 	From: summaries.ArgumentSNode{Name: "b", Index: 1},
					// 	To:   summaries.ArgumentSNode{Name: "no", Index: 2},
					// },
				},
				Method: check.Immutability,
			},
		},
	}

	for _, tc := range tests {
		var sound string
		if tc.want.IsSound {
			sound = "sound"
		} else {
			sound = "unsound"
		}
		name := fmt.Sprintf("%s_%s", tc.summary.Name(), sound)
		t.Run(name, func(t *testing.T) { checkSoundness(t, tc, state) })
	}
}

func TestCheckSummary_Stdlib(t *testing.T) {
	tests := []tcCheck{
		{
			// func Sum(data []byte) [Size]byte
			summary: summaries.NewFunctionFlowSummary("crypto/md5", "Sum",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "data", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: nil,
				Method:   check.General,
			},
		},
		{
			// func Ints(x []int)
			summary: summaries.NewFunctionFlowSummary("sort", "Ints",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
			),
			want: check.SoundnessResult{
				IsSound:  true,
				BadFlows: nil,
				Method:   check.General,
			},
		},
	}

	for _, tc := range tests {
		var sound string
		if tc.want.IsSound {
			sound = "sound"
		} else {
			sound = "unsound"
		}
		name := fmt.Sprintf("%s_%s", tc.summary.Name(), sound)
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("./testdata", "stdlib", tc.summary.Package())
			lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
			if err != nil {
				t.Fatal(err)
			}
			setupConfig(lp)
			state, err := result.Bind(result.Bind(ptr.NewState(lp), dataflow.NewState), check.NewState).Value()
			if err != nil {
				t.Fatalf("failed to load state: %s", err)
			}

			checkSoundness(t, tc, state)
		})
	}
}

type tcCheck struct {
	summary summaries.FrontendDataflowSummary
	want    check.SoundnessResult
	via     check.Method
}

func checkSoundness(t *testing.T, tc tcCheck, state *check.State) {
	got, err := check.CheckSummary(context.Background(), state, tc.summary)
	if err != nil {
		t.Fatalf("failed to check summary: %v", err)
		return
	}

	if tc.want.IsSound != got.IsSound {
		t.Fatalf("soundness mismatch: want %v, got %v\n", tc.want.IsSound, got.IsSound)
		return
	}

	cmpFlow := func(a, b check.Flow) int {
		return strings.Compare(a.String(), b.String())
	}
	slices.SortFunc(tc.want.BadFlows, cmpFlow)
	slices.SortFunc(got.BadFlows, cmpFlow)
	if !slices.Equal(tc.want.BadFlows, got.BadFlows) {
		t.Errorf("bad flows mismatch")
		t.Log("want bad flows:")
		for _, f := range tc.want.BadFlows {
			fname, _ := strings.CutPrefix(f.Fn, tc.summary.Package()+".")
			t.Logf("\t%v: %v -> %v\n", fname, f.From, f.To)
		}
		t.Log("got bad flows:")
		for _, f := range got.BadFlows {
			fname, _ := strings.CutPrefix(f.Fn, tc.summary.Package()+".")
			t.Logf("\t%v: %v -> %v\n", fname, f.From, f.To)
		}
	}

	if tc.want.Method != got.Method {
		t.Errorf("method mismatch: want %v, got %v\n", tc.want.Method, got.Method)
	}
}

func dbgFlows(t *testing.T, flows map[summaries.SummaryNode][]summaries.SummaryNode) {
	for from, tos := range flows {
		logNode(t, from, 1)
		for _, to := range tos {
			logNode(t, to, 2)
		}
	}
}

func logNode(t *testing.T, n summaries.SummaryNode, indent int) {
	switch n := n.(type) {
	case summaries.ArgumentSNode:
		t.Logf("%sARG name: %v, index: %v, path: %v\n", strings.Repeat("\t", indent), n.Name, n.Index, n.ObjectPath)
	case summaries.ReturnSNode:
		t.Logf("%sRET index: %v, path: %v\n", strings.Repeat("\t", indent), n.Index, n.ObjectPath)
	default:
		t.Logf("unsupported summary node type: %T\n", n)
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
