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
			pkg:  pkg,
			name: "singleArgIntraOut",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".singleArgIntraOut",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.General,
				CalleeResults:        nil,
			},
		},
		{
			pkg:  pkg,
			name: "singleArgInterNone",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn:                   pkg + ".singleArgInterNone",
				IsSound:              true,
				UnprovenMustNotFlows: []check.Flow{
					// NOTE Immutability analysis disproved this flow.
					// {
					// 	From: summaries.ArgumentSNode{Name: "x", Index: 0},
					// 	To:   summaries.ReturnSNode{Index: 0},
					// },
				},
				Method: check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn:                   pkg + ".noop",
							Want:                 summaries.DetailedSummary{},
							IsSound:              true,
							UnprovenMustNotFlows: []check.Flow{
								// NOTE Immutability analysis disproved this flow.
								// {
								// 	From: summaries.ArgumentSNode{Name: "arg0", Index: 0},
								// 	To:   summaries.ReturnSNode{Index: 0},
								// },
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "twoArgIntraInout",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".twoArgIntraInout",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "y", Index: 1},
						},
					},
				},
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
						From: summaries.ArgumentSNode{Name: "y", Index: 1},
						To:   summaries.ArgumentSNode{Name: "x", Index: 0},
					},
				},
				Method:        check.Immutability,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "twoArgInterInout",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".twoArgInterInout",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "y", Index: 1},
						},
					},
				},
				IsSound: true,
				// Disproved flow from twoArgInterInout y -> x via immutability
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".setmem",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "src", Index: 1}: {
										summaries.ArgumentSNode{Name: "dst", Index: 0},
									},
								},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.Types,
							CalleeResults:        nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "singleArgIntraGlobal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".singleArgIntraGlobal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true, // TODO global analysis
				UnprovenMustNotFlows: nil,
				Method:               check.General,
				CalleeResults:        nil,
			},
		},
		{
			pkg:  pkg,
			name: "singleArgInterGlobal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".singleArgInterGlobal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true, // TODO global analysis
				UnprovenMustNotFlows: nil,
				Method:               check.General,
				CalleeResults:        nil,
			},
		},
		{
			pkg:  pkg,
			name: "twoArgInterBool",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".twoArgInterBool",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Types,
				CalleeResults:        nil,
			},
		},
		{
			pkg:  pkg,
			name: "twoArgInter",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".twoArgInter",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Types,
				CalleeResults:        nil,
			},
		},
		{
			pkg:  pkg,
			name: "threeArgInter",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".threeArgInter",
				Want: summaries.DetailedSummary{
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
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ReturnSNode{Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
					{
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "b", Index: 2},
					},
					{
						From: summaries.ArgumentSNode{Name: "a", Index: 1},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
				},
				Method: check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".add2",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0}: {
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound: false,
							UnprovenMustNotFlows: []check.Flow{
								{
									From: summaries.ArgumentSNode{Name: "no", Index: 2},
									To:   summaries.ReturnSNode{},
								},
								// NOTE Immutability analysis disproved these flows
								// {
								// 	From: summaries.ArgumentSNode{Name: "a", Index: 0},
								// 	To:   summaries.ArgumentSNode{Name: "no", Index: 2},
								// },
								// {
								// 	From: summaries.ArgumentSNode{Name: "b", Index: 1},
								// 	To:   summaries.ArgumentSNode{Name: "no", Index: 2},
								// },
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "threeArgInterDiffCallees",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn:      pkg + ".threeArgInterDiffCallees",
				IsSound: false,
				Want: summaries.DetailedSummary{
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
				UnprovenMustNotFlows: []check.Flow{
					{
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ReturnSNode{Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
					{
						From: summaries.ArgumentSNode{Name: "no", Index: 0},
						To:   summaries.ArgumentSNode{Name: "b", Index: 2},
					},
					{
						From: summaries.ArgumentSNode{Name: "a", Index: 1},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "no", Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "b", Index: 2},
						To:   summaries.ArgumentSNode{Name: "a", Index: 1},
					},
				},
				Method: check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".add1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0}: {
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							UnprovenMustNotFlows: []check.Flow{
								{
									From: summaries.ArgumentSNode{Name: "no", Index: 2},
									To:   summaries.ReturnSNode{Index: 0},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
					{
						{
							Fn: pkg + ".add2",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0}: {
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							UnprovenMustNotFlows: []check.Flow{
								{
									From: summaries.ArgumentSNode{Name: "no", Index: 2},
									To:   summaries.ReturnSNode{Index: 0},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "propagateFields",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".propagateFields",
				// NOTE This summary is deliberately incorrect:
				// If src cannot flow to dst, then no parameter of addVals can flow to its return.
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "dst", Index: 1}: {
							summaries.ArgumentSNode{Name: "src", Index: 0},
						},
					},
				},
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						From: summaries.ArgumentSNode{Name: "src", Index: 0},
						To:   summaries.ArgumentSNode{Name: "dst", Index: 1},
					},
				},
				Method: check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".addVals",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0}: {
										summaries.ArgumentSNode{Name: "b", Index: 1},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ArgumentSNode{Name: "a", Index: 0},
									},
								},
							},
							IsSound: false,
							UnprovenMustNotFlows: []check.Flow{
								{
									From: summaries.ArgumentSNode{Name: "a", Index: 0},
									To:   summaries.ReturnSNode{Index: 0},
								},
								{
									From: summaries.ArgumentSNode{Name: "b", Index: 1},
									To:   summaries.ReturnSNode{Index: 0},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "propagateFields",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".propagateFields",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "src", Index: 0}: {
							summaries.ArgumentSNode{Name: "dst", Index: 1},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".addVals",
							Want: summaries.DetailedSummary{
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
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.General,
							CalleeResults:        nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "sharedMutation",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".sharedMutation",
				Want: summaries.DetailedSummary{
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
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						From: summaries.ArgumentSNode{Name: "a", Index: 0},
						To:   summaries.ArgumentSNode{Name: "b", Index: 1},
					},
					{
						From: summaries.ArgumentSNode{Name: "b", Index: 1},
						To:   summaries.ArgumentSNode{Name: "a", Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "shared", Index: 2},
						To:   summaries.ArgumentSNode{Name: "a", Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "shared", Index: 2},
						To:   summaries.ArgumentSNode{Name: "b", Index: 1},
					},
				},
				Method: check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".modify",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "val", Index: 0}: {
										summaries.ArgumentSNode{Name: "s", Index: 1},
									},
								},
							},
							IsSound: false,
							UnprovenMustNotFlows: []check.Flow{
								// TODO false-positive: there should not be a flow from modify s -> val.
								// This should be sound.
								{
									From: summaries.ArgumentSNode{Name: "s", Index: 1},
									To:   summaries.ArgumentSNode{Name: "val", Index: 0},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "storePtr",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".storePtr",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
				CalleeResults:        nil,
			},
		},
		{
			pkg:  pkg,
			name: "aliasNoop",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".aliasNoop",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
				CalleeResults:        nil,
			},
		},
		{
			pkg:  pkg,
			name: "alias",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".alias",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
						},
					},
				},
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					// TODO false-positive: there should not be a flow from alias x -> y.
					// This should be sound.
					//
					// The pointer analysis reports that x may-alias y:
					//   [indirect] x may alias with:
					//   [indirect] x (parameter x : ***int) -> n54370
					//   [direct]   y (parameter y : **int) -> n54371
					{
						From: summaries.ArgumentSNode{Name: "x", Index: 0},
						To:   summaries.ArgumentSNode{Name: "y", Index: 1},
					},
				},
				Method:        check.Immutability,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "writeStructPtr",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".writeStructPtr",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
						},
					},
				},
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						// TODO false-positive: there should not be a flow from writeStructPtr x -> y.
						// This should be sound.
						//
						// The pointer analysis does not report any may-aliases for either parameter.
						From: summaries.ArgumentSNode{Name: "x", Index: 0},
						To:   summaries.ArgumentSNode{Name: "y", Index: 1},
					},
				},
				Method:        check.Immutability,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "writeToClosed",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".writeToClosed",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						From: summaries.ArgumentSNode{Name: "y", Index: 1},
						To:   summaries.ReturnSNode{},
					},
				},
				Method: check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".writeToClosed$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "x"}: {
										summaries.FreeVarSNode{Name: "y"},
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound: false,
							UnprovenMustNotFlows: []check.Flow{
								// TODO False-positive from immutability analysis
								{
									From: summaries.FreeVarSNode{Name: "y"},
									To:   summaries.FreeVarSNode{Name: "x"},
								},
								{
									From: summaries.FreeVarSNode{Name: "y"},
									To:   summaries.ReturnSNode{Index: 0},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
						{
							Fn: pkg + ".writeToClosed$1",
							Want: summaries.DetailedSummary{
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
							IsSound: false,
							UnprovenMustNotFlows: []check.Flow{
								// NOTE Technically this flow is realizable but it's from the inferred callee
								// summary: !free <x> -> !free <y> | !free <y> -> !free <x>.
								{
									From: summaries.FreeVarSNode{Name: "x"},
									To:   summaries.ReturnSNode{Index: 0},
								},
								{
									From: summaries.FreeVarSNode{Name: "y"},
									To:   summaries.ReturnSNode{Index: 0},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "nestedClosures",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".nestedClosures",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".nestedClosures$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "z", Index: 0}: {
										summaries.FreeVarSNode{Name: "bv"},
										summaries.ReturnSNode{Index: 0},
									},
									summaries.FreeVarSNode{Name: "bv"}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.Immutability,
							CalleeResults: [][]check.SoundnessResult{
								{
									{
										Fn: pkg + ".nestedClosures$1$1",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
												summaries.FreeVarSNode{Name: "z"}: {
													summaries.ReturnSNode{Index: 0},
												},
											},
										},
										IsSound:              true,
										UnprovenMustNotFlows: nil,
										Method:               check.General,
										CalleeResults:        nil,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "closureShared",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".closureShared",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						From: summaries.ArgumentSNode{Name: "x", Index: 0},
						To:   summaries.ArgumentSNode{Name: "y", Index: 1},
					},
				},
				Method: check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".closureShared$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "x"}: {
										summaries.ReturnSNode{Index: 0},
									},
									summaries.FreeVarSNode{Name: "y"}: {
										summaries.FreeVarSNode{Name: "x"},
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound: false,
							UnprovenMustNotFlows: []check.Flow{
								// TODO Immutability analysis false-positive
								{
									From: summaries.FreeVarSNode{Name: "x"},
									To:   summaries.FreeVarSNode{Name: "y"},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
					{
						{
							Fn: pkg + ".closureShared$2",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "y"}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.General,
							CalleeResults:        nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "noFlowClosure",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".noFlowClosure",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound: false,
				UnprovenMustNotFlows: []check.Flow{
					{
						From: summaries.ArgumentSNode{Name: "x", Index: 0},
						To:   summaries.ReturnSNode{Index: 0},
					},
					{
						From: summaries.ArgumentSNode{Name: "y", Index: 1},
						To:   summaries.ReturnSNode{Index: 0},
					},
				},
				Method:        check.Immutability,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "noFlowClosure",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: pkg + ".noFlowClosure",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: pkg + ".noFlowClosure$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.General,
							CalleeResults:        nil,
						},
					},
				},
			},
		},
		// TODO Don't panic for non-local bound label
		// {
		// pkg: pkg,
		// name: "nestedClosuresInvalid",
		// 	summary: summaries.NewFunctionFlowSummary(pkg, "nestedClosuresInvalid",
		// 		summaries.DetailedSummary{
		// 			Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
		// 				summaries.ArgumentSNode{Name: "x", Index: 0}: {
		// 					summaries.ReturnSNode{Index: 0},
		// 				},
		// 				summaries.ArgumentSNode{Name: "y", Index: 1}: {
		// 					summaries.ReturnSNode{Index: 0},
		// 				},
		// 			},
		// 		},
		// 	),
		// 	want: check.SoundnessResult{
		// 		IsSound:              true,
		// 		UnprovenMustNotFlows: []check.Flow{},
		// 		Method:               check.Immutability,
		// 	},
		// },
	}

	for _, tc := range tests {
		var sound string
		if tc.want.IsSound {
			sound = "sound"
		} else {
			sound = "unsound"
		}
		name := fmt.Sprintf("%s.%s_%s", tc.pkg, tc.name, sound)
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
			pkg:  "crypto/md5",
			name: "Sum",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: "crypto/md5.Sum",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "data", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.General,
				CalleeResults:        nil,
			},
		},
		{
			// func Ints(x []int)
			pkg:  "sort",
			name: "Ints",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: "sort.Ints",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound:              true,
				UnprovenMustNotFlows: nil,
				Method:               check.General,
				CalleeResults:        nil,
			},
		},
		{
			// func json.Marshal(v any) ([]byte, error)
			pkg:  "encoding/json",
			name: "Marshal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Fn: "encoding/json.Marshal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "v", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
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
				UnprovenMustNotFlows: nil,
				Method:               check.Immutability,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Fn: "encoding/json.newEncodeState",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.General,
							CalleeResults:        nil,
						},
					},
					{
						{
							Fn: "(*sync.Pool).Put",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "x", Index: 0}: {
										summaries.ReceiverSNode{},
									},
									summaries.ReceiverSNode{}: {
										summaries.ArgumentSNode{Name: "x", Index: 0},
									},
								},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.General,
							CalleeResults:        nil,
						},
					},
					{
						{
							Fn: "(*bytes.Buffer).Bytes",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ReceiverSNode{}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.General,
							CalleeResults:        nil,
						},
					},
					{
						{
							Fn: "(*encoding/json.encodeState).marshal",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "opts", Index: 1}: {
										summaries.ReceiverSNode{},
										summaries.ArgumentSNode{Name: "v", Index: 0},
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ReceiverSNode{}: {
										summaries.ArgumentSNode{Name: "v", Index: 0},
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.Immutability,
							CalleeResults: [][]check.SoundnessResult{
								{
									{
										Fn: "(*encoding/json.encodeState).marshal$1",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
										},
										IsSound:              true,
										UnprovenMustNotFlows: nil,
										Method:               check.General,
										CalleeResults:        nil,
									},
								},
								{
									{
										Fn: "reflect.ValueOf",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
												summaries.ArgumentSNode{Name: "i", Index: 0}: {
													summaries.ReturnSNode{Index: 0},
												},
											},
										},
										IsSound:              true,
										UnprovenMustNotFlows: nil,
										Method:               check.General,
										CalleeResults:        nil,
									},
								},
								{
									{
										Fn: "(*encoding/json.encodeState).reflectValue",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
												summaries.ArgumentSNode{Name: "opts", Index: 1}: {
													summaries.ReceiverSNode{},
												},
												summaries.ArgumentSNode{Name: "v", Index: 0}: {
													summaries.ReceiverSNode{},
												},
											},
										},
										IsSound:              true,
										UnprovenMustNotFlows: nil,
										Method:               check.Types,
										CalleeResults:        nil,
									},
								},
							},
						},
						{
							Fn: "(*encoding/json.encodeState).marshal",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "opts", Index: 1}: {
										summaries.ReceiverSNode{},
										summaries.ArgumentSNode{Name: "v", Index: 0},
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ReceiverSNode{}: {
										summaries.ArgumentSNode{Name: "v", Index: 0},
									},
									summaries.ArgumentSNode{Name: "v", Index: 0}: {
										summaries.ReceiverSNode{},
									},
								},
							},
							IsSound:              true,
							UnprovenMustNotFlows: nil,
							Method:               check.Immutability,
							CalleeResults: [][]check.SoundnessResult{
								{
									{
										Fn: "(*encoding/json.encodeState).marshal$1",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
										},
										IsSound:              true,
										UnprovenMustNotFlows: nil,
										Method:               check.General,
										CalleeResults:        nil,
									},
								},
								{
									{
										Fn: "reflect.ValueOf",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
												summaries.ArgumentSNode{Name: "i", Index: 0}: {
													summaries.ReturnSNode{Index: 0},
												},
											},
										},
										IsSound:              true,
										UnprovenMustNotFlows: nil,
										Method:               check.General,
										CalleeResults:        nil,
									},
								},
								{
									{
										Fn: "(*encoding/json.encodeState).reflectValue",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
												summaries.ArgumentSNode{Name: "opts", Index: 1}: {
													summaries.ReceiverSNode{},
												},
												summaries.ArgumentSNode{Name: "v", Index: 0}: {
													summaries.ReceiverSNode{},
												},
											},
										},
										IsSound:              true,
										UnprovenMustNotFlows: nil,
										Method:               check.Types,
										CalleeResults:        nil,
									},
								},
							},
						},
					},
				},
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
		name := fmt.Sprintf("%s.%s_%s", tc.pkg, tc.name, sound)
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("./testdata", "stdlib", tc.pkg)
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

type summaryType int

const (
	functionSummary summaryType = iota
	methodSummary
)

type tcCheck struct {
	summary summaries.FrontendDataflowSummary
	pkg     string
	name    string
	typ     summaryType
	want    check.SoundnessResult
	via     check.Method
}

func checkSoundness(t *testing.T, tc tcCheck, state *check.State) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var summary summaries.FrontendDataflowSummary
	switch tc.typ {
	case functionSummary:
		summary = summaries.NewFunctionFlowSummary(tc.pkg, tc.name, tc.want.Want)
	default:
		t.Fatalf("unsupported summary type: %v", tc.typ)
	}

	var got check.SoundnessResult
	var err error
	defer func() {
		if t.Failed() {
			t.Log("want soundness result:")
			t.Log(tc.want)
			t.Log("got soundness result:")
			t.Log(got)
		}
	}()
	got, err = check.CheckSummary(ctx, state, summary)
	if err != nil {
		t.Fatalf("failed to check summary: %v", err)
	}

	checkResult(t, tc.want, got)
}

func checkResult(t *testing.T, want, got check.SoundnessResult) {
	t.Helper()

	if want.Fn != got.Fn {
		// This is an invariant that should be maintained by the test so panic instead of t.Fatal.
		panic(fmt.Errorf("function name mismatch: want %s, got %s", want.Fn, got.Fn))
	}

	if want.Want.String() != got.Want.String() {
		t.Errorf(
			"want summary mismatch for function %s: got %s, want %s", want.Fn, want.Want, got.Want)
		return
	}

	if want.IsSound != got.IsSound {
		t.Errorf("soundness mismatch for function %s: want %v, got %v\n", want.Fn, want.IsSound, got.IsSound)
		return
	}

	cmpFlow := func(a, b check.Flow) int {
		return strings.Compare(a.String(), b.String())
	}
	slices.SortFunc(want.UnprovenMustNotFlows, cmpFlow)
	slices.SortFunc(got.UnprovenMustNotFlows, cmpFlow)
	if !slices.Equal(want.UnprovenMustNotFlows, got.UnprovenMustNotFlows) {
		t.Errorf("unproven must-not-flows mismatch for function %s", want.Fn)
		return
	}

	if want.Method != got.Method {
		t.Errorf("method mismatch for function %s: want %v, got %v\n", want.Fn, want.Method, got.Method)
		return
	}

	if len(want.CalleeResults) != len(got.CalleeResults) {
		t.Errorf("callee results length mismatch for function %s", want.Fn)
		return
	}
	for _, wResults := range want.CalleeResults {
		matchFunc := false
		wFunc := wResults[0].Fn
		for _, gResults := range got.CalleeResults {
			gFunc := gResults[0].Fn
			if wFunc != gFunc {
				continue
			}
			matchFunc = true

			if len(wResults) != len(gResults) {
				t.Errorf(
					"inferred callee summary length mismatch for function %s: want %v, got %v",
					wFunc, len(wResults), len(gResults))
				return
			}

			cmpRes := func(a, b check.SoundnessResult) int {
				return strings.Compare(a.String(), b.String())
			}
			slices.SortFunc(wResults, cmpRes)
			slices.SortFunc(gResults, cmpRes)
			for i := range wResults {
				checkResult(t, wResults[i], gResults[i])
			}
		}
		if !matchFunc {
			t.Errorf("failed to find callee result for function %s in got.CalleeResults", wFunc)
			return
		}
	}
}

func setupConfig(lp *loadprogram.State) {
	level := config.ErrLevel // change this as needed for debugging
	lp.Logger.Level = level
	lp.Logger.SupressWarn = true

	cfg := lp.Config
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false // change this as needed for debugging
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(level)
}
