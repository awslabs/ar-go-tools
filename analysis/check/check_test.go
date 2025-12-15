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
	"time"

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
				IsSound:              true,
				UnprovenMustNotFlows: []check.Flow{},
				Method:               check.General,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "singleArgInterNone",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
			),
			want: check.SoundnessResult{
				IsSound:              true,
				UnprovenMustNotFlows: []check.Flow{
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
				UnprovenMustNotFlows: []check.Flow{
					// NOTE false-positive: pointer analysis claims that x and y have the same node id.
					// Pointer analysis log:
					//==== Generating constraints for cg10524:github.com/awslabs/ar-go-tools/analysis/check/testdata/basic.testTwoArgIntraInout, shared contour
					// # Name: github.com/awslabs/ar-go-tools/analysis/check/testdata/basic.testTwoArgIntraInout
					// # Package: github.com/awslabs/ar-go-tools/analysis/check/testdata/basic
					// # Location: /Volumes/workplace/argot/analysis/check/testdata/basic/main.go:65:6
					// func testTwoArgIntraInout():
					// 0:                                                                entry P:0 S:0
					//         t0 = new int (x)                                                   *int
					//         *t0 = 1:int
					//         t1 = new int (y)                                                   *int
					//         *t1 = -1:int
					//         t2 = twoArgIntraInout(t0, t1)                                        ()
					//         t3 = *t1                                                            int
					//         t4 = new [1]any (varargs)                                       *[1]any
					//         t5 = &t4[0:int]                                                    *any
					//         t6 = make any <- int (t3)                                           any
					//         *t5 = t6
					//         t7 = slice t4[:]                                                  []any
					//         t8 = fmt.Println(t7...)                              (n int, err error)
					//         return
					//
					// ; Creating nodes for local values
					//         create n33318 *int for t0
					//         val[t0] = n33318  (*ssa.Alloc)
					//         create n33319 *int for query
					//         copy n33319 <- n33318
					//         create n33320 *int for t1
					//         val[t1] = n33320  (*ssa.Alloc)
					//         create n33321 *int for query
					//         copy n33321 <- n33320
					//         val[t2] = n0  (*ssa.Call)
					//         create n33322 int for t3
					//         val[t3] = n33322  (*ssa.UnOp)
					//         create n33323 *[1]any for t4
					//         val[t4] = n33323  (*ssa.Alloc)
					//         create n33324 *[1]any for query
					//         copy n33324 <- n33323
					//         create n33325 *any for t5
					//         val[t5] = n33325  (*ssa.IndexAddr)
					//         create n33326 *any for query
					//         copy n33326 <- n33325
					//         create n33327 *any for query.indirect
					//         create n33328 [1]any for alloc
					//         create n33329 any for alloc[*]
					//         localobj[t4] = n33328
					//         localobj[t5] = n33329
					// --
					//         static function call to targets n0 from cg10524:github.com/awslabs/ar-go-tools/analysis/check/testdata/basic.testTwoArgIntraInout
					// ; t3 = *t1
					//         copy n33322 <- n33338
					// ; t4 = new [1]any (varargs)
					//         addr n33323 <- {&n33328}
					// ; t5 = &t4[0:int]
					//         addr n33325 <- {&n33329}
					// ; t6 = make any <- int (t3)
					//         create n33343 int for tagged.T
					//         create n33344 int for tagged.v
					//         copy n33344 <- n33322
					//         localobj[t6] = n33343
					//         addr n33330 <- {&n33343}
					// ; *t5 = t6
					//         copy n33329 <- n33330
					// ; t7 = slice t4[:]
					//         copy n33332 <- n33323
					// ; t8 = fmt.Println(t7...)
					//         call edge static function call -> cg33294:fmt.Println
					//         copy n33295 <- n33332
					//         copy n33334 <- n33296
					//         copy n33335 <- n33297
					//         static function call to targets n0 from cg10524:github.com/awslabs/ar-go-tools/analysis/check/testdata/basic.testTwoArgIntraInout
					// ; return
					//
					// ==== Generating constraints for cg33340:github.com/awslabs/ar-go-tools/analysis/check/testdata/basic.twoArgIntraInout, as called from github.com/awslabs/ar-go-tools/analysis/check/testdata/basic.testTwoArgIntraInout
					// # Name: github.com/awslabs/ar-go-tools/analysis/check/testdata/basic.twoArgIntraInout
					// # Package: github.com/awslabs/ar-go-tools/analysis/check/testdata/basic
					// # Location: /Volumes/workplace/argot/analysis/check/testdata/basic/main.go:33:6
					// func twoArgIntraInout(x *int, y *int):
					// 0:                                                                entry P:0 S:0
					//         t0 = *x                                                             int
					//         *y = t0
					//         return

					// ; Creating nodes for local values
					//         val[x] = n33341  (*ssa.Parameter)
					//         create n49893 *int for query
					//         copy n49893 <- n33341
					//         val[y] = n33342  (*ssa.Parameter)
					//         create n49894 *int for query
					//         copy n49894 <- n33342
					//         create n49895 int for t0
					//         val[t0] = n49895  (*ssa.UnOp)
					// ; t0 = *x
					//         localobj[x] = n0
					//         load n49895 <- n33341[0]
					// ; *y = t0
					//         localobj[y] = n0
					//         store n33342[0] <- n49895
					// ; return

					{
						Fn:   pkg + ".twoArgIntraInout",
						From: summaries.ArgumentSNode{Name: "y", Index: 1},
						To:   summaries.ArgumentSNode{Name: "x", Index: 0},
					},
				},
				Method: check.Immutability,
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
				IsSound: true,
				// Disproved flow from setmem dst -> src via types
				// Disproved flow from twoArgInterInout y -> x via immutability
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
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
				IsSound:              true, // TODO global analysis
				UnprovenMustNotFlows: nil,
				Method:               check.General,
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
				IsSound:              true, // TODO global analysis
				UnprovenMustNotFlows: nil,
				Method:               check.General,
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
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Types,
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
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Types,
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
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						Fn:   pkg + ".threeArgInter",
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ReturnSNode{Index: 0},
					},
					{
						Fn:   pkg + ".threeArgInter",
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
					{
						Fn:   pkg + ".threeArgInter",
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "b", Index: 2},
					},
					{
						Fn:   pkg + ".threeArgInter",
						From: summaries.ArgumentSNode{Name: "a", Index: 1},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						Fn:   pkg + ".threeArgInter",
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						Fn:   pkg + ".threeArgInter",
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
					{
						Fn:   pkg + ".add2",
						From: summaries.ArgumentSNode{Name: "no", Index: 2},
						To:   summaries.ReturnSNode{Index: 0},
					},
					// NOTE Immutability analysis disproved these flows
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
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "threeArgInterDiffCallees",
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
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						Fn:   pkg + ".threeArgInterDiffCallees",
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ReturnSNode{Index: 0},
					},
					{
						Fn:   pkg + ".threeArgInterDiffCallees",
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
					{
						Fn:   pkg + ".threeArgInterDiffCallees",
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "b", Index: 2},
					},
					{
						Fn:   pkg + ".threeArgInterDiffCallees",
						From: summaries.ArgumentSNode{Name: "a", Index: 1},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						Fn:   pkg + ".threeArgInterDiffCallees",
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						Fn:   pkg + ".threeArgInterDiffCallees",
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
					{
						Fn:   pkg + ".add1",
						From: summaries.ArgumentSNode{Name: "no", Index: 2},
						To:   summaries.ReturnSNode{Index: 0},
					},
					{
						Fn:   pkg + ".add2",
						From: summaries.ArgumentSNode{Name: "no", Index: 2},
						To:   summaries.ReturnSNode{Index: 0},
					},
				},
				Method: check.Immutability,
			},
		},
		{
			// NOTE This summary is deliberately incorrect:
			// If src cannot flow to dst, then no parameter of addVals can flow to its return.
			summary: summaries.NewFunctionFlowSummary(pkg, "propagateFields",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "dst", Index: 1}: {
							summaries.ArgumentSNode{Name: "src", Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						Fn:   pkg + ".propagateFields",
						From: summaries.ArgumentSNode{Name: "src", Index: 0},
						To:   summaries.ArgumentSNode{Name: "dst", Index: 1},
					},
					{
						Fn:   pkg + ".addVals",
						From: summaries.ArgumentSNode{Name: "a", Index: 0},
						To:   summaries.ReturnSNode{Index: 0},
					},
					{
						Fn:   pkg + ".addVals",
						From: summaries.ArgumentSNode{Name: "b", Index: 1},
						To:   summaries.ReturnSNode{Index: 0},
					},
				},
				Method: check.Immutability,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "propagateFields",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "src", Index: 0}: {
							summaries.ArgumentSNode{Name: "dst", Index: 1},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "sharedMutation",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
							summaries.ArgumentSNode{Name: "shared", Index: 2},
						},
						summaries.ArgumentSNode{Name: "b", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
							summaries.ArgumentSNode{Name: "shared", Index: 2},
						},
						summaries.ArgumentSNode{Name: "shared", Index: 2}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				// TODO false-positive: there should not be a flow from modify s -> val.
				// This should be sound.
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						Fn:   pkg + ".sharedMutation",
						From: summaries.ArgumentSNode{Name: "a", Index: 0},
						To:   summaries.ArgumentSNode{Name: "b", Index: 1},
					},
					{
						Fn:   pkg + ".sharedMutation",
						From: summaries.ArgumentSNode{Name: "b", Index: 1},
						To:   summaries.ArgumentSNode{Name: "a", Index: 0},
					},
					{
						Fn:   pkg + ".sharedMutation",
						From: summaries.ArgumentSNode{Name: "shared", Index: 2},
						To:   summaries.ArgumentSNode{Name: "a", Index: 0},
					},
					{
						Fn:   pkg + ".sharedMutation",
						From: summaries.ArgumentSNode{Name: "shared", Index: 2},
						To:   summaries.ArgumentSNode{Name: "b", Index: 1},
					},
					{
						Fn:   pkg + ".modify",
						From: summaries.ArgumentSNode{Name: "s", Index: 1},
						To:   summaries.ArgumentSNode{Name: "val", Index: 0},
					},
				},
				Method: check.Immutability,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "storePtr",
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
				IsSound:              true,
				UnprovenMustNotFlows: []check.Flow{},
				Method:               check.Immutability,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "aliasNoop",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
			),
			want: check.SoundnessResult{
				IsSound:              true,
				UnprovenMustNotFlows: []check.Flow{},
				Method:               check.Immutability,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "alias",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				// TODO false-positive: there should not be a flow from alias x -> y.
				// This should be sound.
				//
				// The pointer analysis reports that x may-alias y:
				//   [indirect] x may alias with:
				//   [indirect] x (parameter x : ***int) -> n54370
				//   [direct]   y (parameter y : **int) -> n54371
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						Fn:   pkg + ".alias",
						From: summaries.ArgumentSNode{Name: "x", Index: 0},
						To:   summaries.ArgumentSNode{Name: "y", Index: 1},
					},
				},
				Method: check.Immutability,
			},
		},
		{
			summary: summaries.NewFunctionFlowSummary(pkg, "writeStructPtr",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				// TODO false-positive: there should not be a flow from writeStructPtr x -> y.
				// This should be sound.
				//
				// The pointer analysis does not report any may-aliases for either parameter.
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						Fn:   pkg + ".writeStructPtr",
						From: summaries.ArgumentSNode{Name: "x", Index: 0},
						To:   summaries.ArgumentSNode{Name: "y", Index: 1},
					},
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
	if testing.Short() {
		t.Skip("skipping due to short mode")
	}

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
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.General,
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
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.General,
			},
		},
		{
			// func json.Marshal(v any) ([]byte, error)
			summary: summaries.NewFunctionFlowSummary("encoding/json", "Marshal",
				summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "v", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
			),
			want: check.SoundnessResult{
				IsSound: true,
				// NOTE For some reason, the pointer analysis does not record any Labels for any
				// errors returned in json.Marshal, meaning that the error return values are
				// trivially immutable.
				//
				// I think this is because the pointer analysis is not detecting the error value
				// allocation in the recover check:
				//   func (e *encodeState) marshal(v any, opts encOpts) (err error) {
				//   	defer func() {
				//   		if r := recover(); r != nil {
				//   			if je, ok := r.(jsonError); ok {
				//   				err = je.error // <- write to err here
				//   			} else {
				//   				panic(r)
				//   			}
				//   		}
				//   	}()
				UnprovenMustNotFlows: []check.Flow{},
				Method:               check.Immutability,
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
			lp, err := analysistest.LoadTest(
				testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
			if err != nil {
				t.Fatal(err)
			}
			setupConfig(lp)
			state, err := result.Bind(
				result.Bind(ptr.NewState(lp), dataflow.NewState), check.NewState).Value()
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
	subset  bool // subset is true if got should be a subset of want (for nondeterministic tests).
	via     check.Method
}

func checkSoundness(t *testing.T, tc tcCheck, state *check.State) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var got check.SoundnessResult
	var err error
	defer func() {
		if t.Failed() {
			t.Log("want unproven must-not-flows:")
			dbgFlows(t, tc.want.UnprovenMustNotFlows, tc.summary.Package())
			t.Log("got unproven must-not-flows:")
			dbgFlows(t, got.UnprovenMustNotFlows, tc.summary.Package())
		}
	}()
	got, err = check.CheckSummary(ctx, state, tc.summary)
	if err != nil {
		t.Fatalf("failed to check summary: %v", err)
		return
	}

	if tc.want.IsSound != got.IsSound {
		t.Fatalf("soundness mismatch: want %v, got %v\n", tc.want.IsSound, got.IsSound)
		return
	}

	if tc.subset {
		// Check that got is a subset of want.
		for _, gfl := range got.UnprovenMustNotFlows {
			if !slices.Contains(tc.want.UnprovenMustNotFlows, gfl) {
				t.Errorf("failed to find got must-not-flow %v in want must-not-flows\n", gfl)
			}
		}
	} else {
		cmpFlow := func(a, b check.Flow) int {
			return strings.Compare(a.String(), b.String())
		}
		slices.SortFunc(tc.want.UnprovenMustNotFlows, cmpFlow)
		slices.SortFunc(got.UnprovenMustNotFlows, cmpFlow)
		// Check that got and want are equal.
		if !slices.Equal(tc.want.UnprovenMustNotFlows, got.UnprovenMustNotFlows) {
			t.Errorf("unproven must-not-flows mismatch")
		}
	}

	if tc.want.Method != got.Method {
		t.Errorf("method mismatch: want %v, got %v\n", tc.want.Method, got.Method)
	}
}

func dbgFlows(t *testing.T, flows []check.Flow, pkg string) {
	t.Helper()
	for _, fl := range flows {
		fname, _ := strings.CutPrefix(fl.Fn, pkg+".")
		t.Logf("\t%v: %v -> %v\n", fname, fl.From, fl.To)
	}
}

func setupConfig(lp *loadprogram.State) {
	level := config.TraceLevel // change this as needed for debugging
	lp.Logger.Level = level
	lp.Logger.SupressWarn = true

	cfg := lp.Config
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false // change this as needed for debugging
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(level)
}
