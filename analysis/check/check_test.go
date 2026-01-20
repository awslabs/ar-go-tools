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
	"golang.org/x/tools/go/ssa"
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
				Name: pkg + ".singleArgIntraOut",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "singleArgInterNone",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name:    pkg + ".singleArgInterNone",
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						// NOTE Immutability analysis disproved this flow.
						// {
						// 	From: summaries.ArgumentSNode{Name: "x", Index: 0},
						// 	To:   summaries.ReturnSNode{Index: 0},
						// },
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name:    pkg + ".noop",
							Want:    summaries.DetailedSummary{},
							IsSound: true,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// NOTE Immutability analysis disproved this flow.
									// {
									// 	From: summaries.ArgumentSNode{Name: "arg0", Index: 0},
									// 	To:   summaries.ReturnSNode{Index: 0},
									// },
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
			name: "twoArgIntraInout",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".twoArgIntraInout",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "y", Index: 1},
						},
					},
				},
				IsSound: false,
				Unsoundness: check.Unsoundness{
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
				Name: pkg + ".twoArgInterInout",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "y", Index: 1},
						},
					},
				},
				IsSound: true,
				// Disproved flow from twoArgInterInout y -> x via immutability
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".setmem",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "src", Index: 1}: {
										summaries.ArgumentSNode{Name: "dst", Index: 0},
									},
								},
							},
							IsSound: true,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
							},
							Method:        check.Types,
							CalleeResults: nil,
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
				Name: pkg + ".singleArgIntraGlobal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound: false, // TODO global analysis
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "singleArgInterGlobal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".singleArgInterGlobal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound: false, // TODO global analysis
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "twoArgInterBool",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".twoArgInterBool",
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
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Types,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "twoArgInter",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".twoArgInter",
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
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Types,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "threeArgInter",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".threeArgInter",
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
				Unsoundness: check.Unsoundness{
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
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".add2",
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
							Unsoundness: check.Unsoundness{
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
				Name:    pkg + ".threeArgInterDiffCallees",
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
				Unsoundness: check.Unsoundness{
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
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".add1",
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
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.ArgumentSNode{Name: "no", Index: 2},
										To:   summaries.ReturnSNode{Index: 0},
									},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
					{
						{
							Name: pkg + ".add2",
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
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.ArgumentSNode{Name: "no", Index: 2},
										To:   summaries.ReturnSNode{Index: 0},
									},
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
				Name: pkg + ".propagateFields",
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
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "src", Index: 0},
							To:   summaries.ArgumentSNode{Name: "dst", Index: 1},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".addVals",
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
							Unsoundness: check.Unsoundness{
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
				Name: pkg + ".propagateFields",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "src", Index: 0}: {
							summaries.ArgumentSNode{Name: "dst", Index: 1},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".addVals",
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
							IsSound: true,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
							},
							Method:        check.General,
							CalleeResults: nil,
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
				Name: pkg + ".sharedMutation",
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
				Unsoundness: check.Unsoundness{
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
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".modify",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "val", Index: 0}: {
										summaries.ArgumentSNode{Name: "s", Index: 1},
									},
								},
							},
							IsSound: false,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// TODO false-positive: there should not be a flow from
									// modify s -> val.
									// This should be sound.
									{
										From: summaries.ArgumentSNode{Name: "s", Index: 1},
										To:   summaries.ArgumentSNode{Name: "val", Index: 0},
									},
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
				Name: pkg + ".storePtr",
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
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "aliasNoop",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".aliasNoop",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: nil,
			},
		},
		{
			pkg:  pkg,
			name: "alias",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".alias",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
						},
					},
				},
				IsSound: false,
				Unsoundness: check.Unsoundness{
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
				Name: pkg + ".writeStructPtr",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
						},
					},
				},
				IsSound: false,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							// TODO false-positive: there should not be a flow from
							// writeStructPtr x -> y.
							// This should be sound.
							//
							// The pointer analysis does not report any may-aliases for either
							// parameter.
							From: summaries.ArgumentSNode{Name: "x", Index: 0},
							To:   summaries.ArgumentSNode{Name: "y", Index: 1},
						},
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
				Name: pkg + ".writeToClosed",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound: false,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "y", Index: 1},
							To:   summaries.ReturnSNode{},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".writeToClosed$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "x"}: {
										summaries.FreeVarSNode{Name: "y"},
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound: false,
							Unsoundness: check.Unsoundness{
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
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
						{
							Name: pkg + ".writeToClosed$1",
							Want: summaries.DetailedSummary{
								// NOTE This second inferred summary is fine because it does not
								// include a flow from x to the closure's return, which means y
								// cannot flow to the return.
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
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// NOTE Technically this flow is realizable, but it's from the
									// inferred callee
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
				Name: pkg + ".nestedClosures",
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
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".nestedClosures$1",
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
							IsSound: true,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
							},
							Method: check.Recursive,
							CalleeResults: [][]check.SoundnessResult{
								{
									{
										Name: pkg + ".nestedClosures$1$1",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
												summaries.FreeVarSNode{Name: "z"}: {
													summaries.ReturnSNode{Index: 0},
												},
											},
										},
										IsSound: true,
										Unsoundness: check.Unsoundness{
											UnprovenMustNotFlows: nil,
										},
										Method:        check.General,
										CalleeResults: nil,
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
				Name: pkg + ".closureShared",
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
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "x", Index: 0},
							To:   summaries.ArgumentSNode{Name: "y", Index: 1},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".closureShared$1",
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
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// TODO Immutability analysis false-positive
									{
										From: summaries.FreeVarSNode{Name: "x"},
										To:   summaries.FreeVarSNode{Name: "y"},
									},
								},
							},
							Method:        check.Immutability,
							CalleeResults: nil,
						},
					},
					{
						{
							Name: pkg + ".closureShared$2",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "y"}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							IsSound: true,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
							},
							Method:        check.General,
							CalleeResults: nil,
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
				Name: pkg + ".noFlowClosure",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound: false,
				Unsoundness: check.Unsoundness{
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
				Name: pkg + ".noFlowClosure",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".noFlowClosure$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
							},
							IsSound: true,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
							},
							Method:        check.General,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "nestedClosuresInvalid",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".nestedClosuresInvalid",
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
				// NOTE Summary is unsound because closure has a non-local bound label
				IsSound: false,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "x", Index: 0},
							To:   summaries.ArgumentSNode{Name: "y", Index: 1},
						},
						{
							From: summaries.ArgumentSNode{Name: "y", Index: 1},
							To:   summaries.ArgumentSNode{Name: "x", Index: 0},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name:    pkg + ".nestedClosuresInvalid$1",
							IsSound: false,
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "x"}: {
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.FreeVarSNode{Name: "x"},
										To:   summaries.FreeVarSNode{Name: "y"},
									},
									{
										From: summaries.FreeVarSNode{Name: "y"},
										To:   summaries.FreeVarSNode{Name: "x"},
									},
									{
										From: summaries.FreeVarSNode{Name: "y"},
										To:   summaries.ReturnSNode{Index: 0},
									},
								},
							},
							Method: check.Recursive,
							CalleeResults: [][]check.SoundnessResult{
								{
									{
										Name: pkg + ".nestedClosuresInvalid$1$1",
										Want: summaries.DetailedSummary{
											Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
												summaries.FreeVarSNode{Name: "x"}: {
													summaries.ReturnSNode{Index: 0},
												},
											},
										},
										IsSound: false,
										Unsoundness: check.Unsoundness{
											UnprovenMustNotFlows: []check.Flow{
												{
													From: summaries.FreeVarSNode{Name: "x"},
													To:   summaries.FreeVarSNode{Name: "y"},
												},
												{
													From: summaries.FreeVarSNode{Name: "y"},
													To:   summaries.FreeVarSNode{Name: "x"},
												},
												{
													From: summaries.FreeVarSNode{Name: "y"},
													To:   summaries.ReturnSNode{Index: 0},
												},
											},
										},
										Method:        check.Immutability,
										CalleeResults: nil,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// sinkCaller is unsound because it's calling a sink function
			// another solution would be to allow the user to promote the summarized function to a sink
			pkg:  pkg,
			name: "sinkCaller",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".sinkCaller",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound: false,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
			},
		},
		{
			// sourceCaller is unsound because it's calling a source function
			pkg:  pkg,
			name: "sourceCaller",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".sourceCaller",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound: false,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
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
		t.Run(name, func(t *testing.T) { checkSoundness(t, tc, state) })
	}
}

// TestCheckSummary_Fields tests field-sensitive summaries.
func TestCheckSummary_Fields(t *testing.T) {
	dir := filepath.Join("./testdata", "fields")
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

	pkg := "github.com/awslabs/ar-go-tools/analysis/check/testdata/fields"
	tests := []tcCheck{
		{
			pkg:  pkg,
			name: "incFieldBy",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".incFieldBy",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "n", Index: 1}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".field.value"},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Types,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "propagateFieldsField",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".propagateFieldsField",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".field.value"}: {
							summaries.ArgumentSNode{Name: "dst", Index: 1, ObjectPath: ".field"},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "propagateFieldsOther",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".propagateFieldsOther",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".other.value"}: {
							summaries.ArgumentSNode{Name: "dst", Index: 1, ObjectPath: ".other"},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "propagateFieldsBoth",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".propagateFieldsBoth",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".field.value"}: {
							summaries.ArgumentSNode{Name: "dst", Index: 1, ObjectPath: ".other"},
						},
						summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".other.value"}: {
							summaries.ArgumentSNode{Name: "dst", Index: 1, ObjectPath: ".other"},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "incRight",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".incRight",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "n", Index: 1}: {
							summaries.ArgumentSNode{Name: "t", Index: 0, ObjectPath: ".right.n"},
						},
					},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{},
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
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
				Name: "crypto/md5.Sum",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "data", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				// NOTE The most-general summary for function (*md5.digest).Write is unsound because
				// it accesses a global.
				// NOTE: but that global is only written in init, so we consider the most-general summary sound.
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
			},
		},
		{
			// func Ints(x []int)
			pkg:  "sort",
			name: "Ints",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: "sort.Ints",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				},
				IsSound: true,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
			},
		},
		{
			// func json.Marshal(v any) ([]byte, error)
			pkg:  "encoding/json",
			name: "Marshal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: "encoding/json.Marshal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "v", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				// NOTE The most-general summary of json.Marshal is unsound because it reads from
				// the global variable `encodeStatePool`.
				IsSound: false,
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
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: nil,
				// CalleeResults: [][]check.SoundnessResult{
				// 	{
				// 		{
				// 			Name: "encoding/json.newEncodeState",
				// 			Want: summaries.DetailedSummary{
				// 				Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				// 			},
				// 			IsSound: true,
				// 			Unsoundness: check.Unsoundness{
				// 				UnprovenMustNotFlows: nil,
				// 			},
				// 			Method:        check.General,
				// 			CalleeResults: nil,
				// 		},
				// 	},
				// 	{
				// 		{
				// 			Name: "(*sync.Pool).Put",
				// 			Want: summaries.DetailedSummary{
				// 				Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 					summaries.ArgumentSNode{Name: "x", Index: 0}: {
				// 						summaries.ReceiverSNode{},
				// 					},
				// 					summaries.ReceiverSNode{}: {
				// 						summaries.ArgumentSNode{Name: "x", Index: 0},
				// 					},
				// 				},
				// 			},
				// 			IsSound: true,
				// 			Unsoundness: check.Unsoundness{
				// 				UnprovenMustNotFlows: nil,
				// 			},
				// 			Method:        check.General,
				// 			CalleeResults: nil,
				// 		},
				// 	},
				// 	{
				// 		{
				// 			Name: "(*bytes.Buffer).Bytes",
				// 			Want: summaries.DetailedSummary{
				// 				Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 					summaries.ReceiverSNode{}: {
				// 						summaries.ReturnSNode{Index: 0},
				// 					},
				// 				},
				// 			},
				// 			IsSound: true,
				// 			Unsoundness: check.Unsoundness{
				// 				UnprovenMustNotFlows: nil,
				// 			},
				// 			Method:        check.General,
				// 			CalleeResults: nil,
				// 		},
				// 	},
				// 	{
				// 		{
				// 			Name: "(*encoding/json.encodeState).marshal",
				// 			Want: summaries.DetailedSummary{
				// 				Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 					summaries.ArgumentSNode{Name: "opts", Index: 1}: {
				// 						summaries.ReceiverSNode{},
				// 						summaries.ArgumentSNode{Name: "v", Index: 0},
				// 						summaries.ReturnSNode{Index: 0},
				// 					},
				// 					summaries.ReceiverSNode{}: {
				// 						summaries.ArgumentSNode{Name: "v", Index: 0},
				// 						summaries.ReturnSNode{Index: 0},
				// 					},
				// 				},
				// 			},
				// 			IsSound: true,
				// 			Unsoundness: check.Unsoundness{
				// 				UnprovenMustNotFlows: nil,
				// 			},
				// 			Method: check.Immutability,
				// 			CalleeResults: [][]check.SoundnessResult{
				// 				{
				// 					{
				// 						Name: "(*encoding/json.encodeState).marshal$1",
				// 						Want: summaries.DetailedSummary{
				// 							Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				// 						},
				// 						IsSound: true,
				// 						Unsoundness: check.Unsoundness{
				// 							UnprovenMustNotFlows: nil,
				// 						},
				// 						Method:        check.General,
				// 						CalleeResults: nil,
				// 					},
				// 				},
				// 				{
				// 					{
				// 						Name: "reflect.ValueOf",
				// 						Want: summaries.DetailedSummary{
				// 							Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 								summaries.ArgumentSNode{Name: "i", Index: 0}: {
				// 									summaries.ReturnSNode{Index: 0},
				// 								},
				// 							},
				// 						},
				// 						IsSound: true,
				// 						Unsoundness: check.Unsoundness{
				// 							UnprovenMustNotFlows: nil,
				// 						},
				// 						Method:        check.General,
				// 						CalleeResults: nil,
				// 					},
				// 				},
				// 				{
				// 					{
				// 						Name: "(*encoding/json.encodeState).reflectValue",
				// 						Want: summaries.DetailedSummary{
				// 							Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 								summaries.ArgumentSNode{Name: "opts", Index: 1}: {
				// 									summaries.ReceiverSNode{},
				// 								},
				// 								summaries.ArgumentSNode{Name: "v", Index: 0}: {
				// 									summaries.ReceiverSNode{},
				// 								},
				// 							},
				// 						},
				// 						IsSound: true,
				// 						Unsoundness: check.Unsoundness{
				// 							UnprovenMustNotFlows: nil,
				// 						},
				// 						Method:        check.Types,
				// 						CalleeResults: nil,
				// 					},
				// 				},
				// 			},
				// 		},
				// 		{
				// 			Name: "(*encoding/json.encodeState).marshal",
				// 			Want: summaries.DetailedSummary{
				// 				Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 					summaries.ArgumentSNode{Name: "opts", Index: 1}: {
				// 						summaries.ReceiverSNode{},
				// 						summaries.ArgumentSNode{Name: "v", Index: 0},
				// 						summaries.ReturnSNode{Index: 0},
				// 					},
				// 					summaries.ReceiverSNode{}: {
				// 						summaries.ArgumentSNode{Name: "v", Index: 0},
				// 					},
				// 					summaries.ArgumentSNode{Name: "v", Index: 0}: {
				// 						summaries.ReceiverSNode{},
				// 					},
				// 				},
				// 			},
				// 			IsSound: true,
				// 			Unsoundness: check.Unsoundness{
				// 				UnprovenMustNotFlows: nil,
				// 			},
				// 			Method: check.Immutability,
				// 			CalleeResults: [][]check.SoundnessResult{
				// 				{
				// 					{
				// 						Name: "(*encoding/json.encodeState).marshal$1",
				// 						Want: summaries.DetailedSummary{
				// 							Flows: map[summaries.SummaryNode][]summaries.SummaryNode{},
				// 						},
				// 						IsSound: true,
				// 						Unsoundness: check.Unsoundness{
				// 							UnprovenMustNotFlows: nil,
				// 						},
				// 						Method:        check.General,
				// 						CalleeResults: nil,
				// 					},
				// 				},
				// 				{
				// 					{
				// 						Name: "reflect.ValueOf",
				// 						Want: summaries.DetailedSummary{
				// 							Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 								summaries.ArgumentSNode{Name: "i", Index: 0}: {
				// 									summaries.ReturnSNode{Index: 0},
				// 								},
				// 							},
				// 						},
				// 						IsSound: true,
				// 						Unsoundness: check.Unsoundness{
				// 							UnprovenMustNotFlows: nil,
				// 						},
				// 						Method:        check.General,
				// 						CalleeResults: nil,
				// 					},
				// 				},
				// 				{
				// 					{
				// 						Name: "(*encoding/json.encodeState).reflectValue",
				// 						Want: summaries.DetailedSummary{
				// 							Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				// 								summaries.ArgumentSNode{Name: "opts", Index: 1}: {
				// 									summaries.ReceiverSNode{},
				// 								},
				// 								summaries.ArgumentSNode{Name: "v", Index: 0}: {
				// 									summaries.ReceiverSNode{},
				// 								},
				// 							},
				// 						},
				// 						IsSound: true,
				// 						Unsoundness: check.Unsoundness{
				// 							UnprovenMustNotFlows: nil,
				// 						},
				// 						Method:        check.Types,
				// 						CalleeResults: nil,
				// 					},
				// 				},
				// 			},
				// 		},
				// 	},
				// },
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
	pkg  string
	name string
	typ  summaryType
	want check.SoundnessResult
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

	var got []check.SoundnessResult
	var err error
	defer func() {
		if t.Failed() {
			t.Log("want soundness result:")
			t.Log(tc.want)
			t.Log("got soundness result:")
			t.Log(got)
		}
	}()
	specs := []dataflow.ScanningSpec{
		{
			IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
				return dataflow.IsNodeOfInterest(state.State, node)
			},
		},
	}
	got, _, err = check.CheckSummary(ctx, state, summary, specs, false)
	if err != nil {
		t.Fatalf("failed to check summary: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	checkResult(t, tc.want, got[0])
}

func checkResult(t *testing.T, want, got check.SoundnessResult) {
	t.Helper()
	// TODO: extend tests not to ignore callee results.
	ignoreCalleeResults := true
	if want.Name != got.Name {
		// This is an invariant that should be maintained by the test so panic instead of t.Fatal.
		panic(fmt.Errorf("function name mismatch: want %s, got %s", want.Name, got.Name))
	}

	if want.Want.String() != got.Want.String() {
		t.Errorf(
			"want summary mismatch for function %s: got %s, want %s", want.Name, want.Want, got.Want)
		return
	}

	if want.IsSound != got.IsSound {
		t.Errorf(
			"soundness mismatch for function %s: want %v, got %v\n",
			want.Name, want.IsSound, got.IsSound)
		return
	}

	cmpFlow := func(a, b check.Flow) int {
		return strings.Compare(a.String(), b.String())
	}
	slices.SortFunc(want.Unsoundness.UnprovenMustNotFlows, cmpFlow)
	slices.SortFunc(got.Unsoundness.UnprovenMustNotFlows, cmpFlow)
	if !slices.Equal(want.Unsoundness.UnprovenMustNotFlows, got.Unsoundness.UnprovenMustNotFlows) {
		t.Errorf("unproven must-not-flows mismatch for function %s", want.Name)
		return
	}

	if want.Method != got.Method {
		t.Errorf(
			"method mismatch for function %s: want %v, got %v\n", want.Name, want.Method, got.Method)
		return
	}
	if ignoreCalleeResults {
		return
	}

	if len(want.CalleeResults) != len(got.CalleeResults) {
		t.Errorf("callee results length mismatch for function %s", want.Name)
		return
	}
	for _, wResults := range want.CalleeResults {
		matchFunc := false
		wFunc := wResults[0].Name
		for _, gResults := range got.CalleeResults {
			gFunc := gResults[0].Name
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
	lp.Logger.SupressWarn = false

	cfg := lp.Config
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false // change this as needed for debugging
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.CheckIgnoresUnsound = false
	cfg.LogLevel = int(level)
	// Always ignore pre-defined summaries
	cfg.DataflowProblems.CheckIgnoresPredefined = true
}
