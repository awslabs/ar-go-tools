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
	"go/token"
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
							// NOTE To test redundant summary flows
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Sound,
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
				Name:      pkg + ".singleArgInterNone",
				Soundness: check.Sound,
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
							Name:      pkg + ".noop",
							Want:      summaries.DetailedSummary{},
							Soundness: check.Sound,
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
				Soundness: check.Unsound,
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
				Method:        check.Read,
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
				Soundness: check.Sound,
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
							Soundness: check.Sound,
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
				Soundness: check.Soundy, // TODO global analysis
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
					CheckFeatures: check.UnsoundCheckFeatures{
						GlobalUsages: []token.Position{{}, {}},
					},
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
				Soundness: check.Soundy, // TODO global analysis
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
					CheckFeatures: check.UnsoundCheckFeatures{
						GlobalUsages: []token.Position{{}, {}},
					},
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
				Soundness: check.Sound,
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
				Soundness: check.Sound,
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
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{},
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
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{},
							},
							Method:        check.Read,
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
				Name:      pkg + ".threeArgInterDiffCallees",
				Soundness: check.Sound,
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
					UnprovenMustNotFlows: []check.Flow{},
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
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{},
							},
							Method:        check.Read,
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
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{},
							},
							Method:        check.Read,
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
				// If src cannot flow to dst, then the maximal callee summary for addVals
				// that doesn't violate the must-not-flow is a <-> b (arg-to-arg flows that
				// map to self-flows src -> src in the parent).
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "dst", Index: 1}: {
							summaries.ArgumentSNode{Name: "src", Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
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
							Soundness: check.Unsound,
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
							Method:        check.Read,
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
				Soundness: check.Sound,
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
							Soundness: check.Sound,
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
				Soundness: check.Unsound,
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
							Soundness: check.Unsound,
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
							Method:        check.Read,
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
				Soundness: check.Sound,
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
				Soundness: check.Sound,
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
				Soundness: check.Unsound,
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
				Method:        check.Read,
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
				Soundness: check.Unsound,
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
				Method:        check.Read,
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
				Soundness: check.Unsound,
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
									summaries.FreeVarSNode{Name: "y"}: {
										summaries.FreeVarSNode{Name: "x"},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// TODO False-positive from read analysis
									{
										From: summaries.FreeVarSNode{Name: "y"},
										To:   summaries.ReturnSNode{Index: 0},
									},
								},
							},
							Method:        check.Read,
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
				Soundness: check.Sound,
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
							Soundness: check.Sound,
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
										Soundness: check.Sound,
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
				Soundness: check.Unsound,
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
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// TODO Read analysis false-positive
									{
										From: summaries.FreeVarSNode{Name: "x"},
										To:   summaries.FreeVarSNode{Name: "y"},
									},
								},
							},
							Method:        check.Read,
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
							Soundness: check.Sound,
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
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						// NOTE Proven by read analysis.
						// {
						// 	From: summaries.ArgumentSNode{Name: "x", Index: 0},
						// 	To:   summaries.ReturnSNode{Index: 0},
						// },
						// {
						// 	From: summaries.ArgumentSNode{Name: "y", Index: 1},
						// 	To:   summaries.ReturnSNode{Index: 0},
						// },
					},
				},
				Method:        check.Read,
				CalleeResults: nil,
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
				Soundness: check.Unsound,
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
							Name:      pkg + ".nestedClosuresInvalid$1",
							Soundness: check.Unsound,
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
										Soundness: check.Unsound,
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
										Method:        check.Read,
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
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
					CheckFeatures: check.UnsoundCheckFeatures{
						EntryPointUsages: []token.Position{{}},
					},
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
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
					CheckFeatures: check.UnsoundCheckFeatures{
						EntryPointUsages: []token.Position{{}},
					},
				},
				Method:        check.General,
				CalleeResults: nil,
			},
		},
	}

	for _, tc := range tests {
		if tc.name == "closureShared" {
			// TODO Enable this test once we can encode this case into the test expectation.
			// NOTE t.Skip() on the parent t would halt this whole loop, silently skipping every
			// subsequent test case in tests[]; continue only skips this one case.
			continue
		}
		name := fmt.Sprintf("%s.%s_%s", tc.pkg, tc.name, tc.want.Soundness)
		t.Run(name, func(t *testing.T) { checkSoundness(t, tc, state) })
	}
}

// TestCheckSummary_ClosureRejected checks that checkSummary refuses to check a summary for a
// TestCheckSummary_ClosureRejected checks that checkSummary rejects a top-level target that is a
// closure with free variables, since the checkable summary format has no syntax for them.
func TestCheckSummary_ClosureRejected(t *testing.T) {
	dir := filepath.Join("./testdata", "basic")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	state, err := result.Bind(
		result.Bind(ptr.NewState(lp), dataflow.NewState), check.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}

	// nestedClosures' inner closure captures free variables (bv, z).
	f := findFunc(state, "nestedClosures$1$1")
	if f == nil {
		t.Fatal("failed to find nestedClosures$1$1 (inner closure)")
	}
	if len(f.FreeVars) == 0 {
		t.Fatalf("test setup invalid: %s has no free variables", f)
	}

	summary := summaries.NewFunctionFlowSummary(
		"github.com/awslabs/ar-go-tools/analysis/check/testdata/basic", f.Name(),
		summaries.DetailedSummary{})
	specs := []dataflow.ScanningSpec{
		{
			IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
				return dataflow.IsNodeOfInterest(state.State, node)
			},
		},
	}
	_, _, err = check.CheckSummary(context.Background(), state, summary, specs, true)
	if err == nil {
		t.Fatalf("expected an error checking a closure with free variables, got nil")
	}
}

// TestCheckSummary_Naive tests the naive checking method, which computes the full transitively
// closed summary of a function and compares it directly against the summary being checked (rather
// than searching for individual unproven must-not-flows). It reuses the transitive_closure testdata
// package, which already has fixtures exercising field-sensitivity.
func TestCheckSummary_Naive(t *testing.T) {
	dir := filepath.Join("./testdata", "transitive_closure")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	state, err := result.Bind(
		result.Bind(ptr.NewState(lp), dataflow.NewState), check.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}

	pkg := "github.com/awslabs/ar-go-tools/analysis/check/testdata/transitive_closure"
	tests := []tcCheck{
		{
			// fooTop(s string) string { return foo0(s, s) }: s flows to the return.
			pkg:   pkg,
			name:  "fooTop",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".fooTop",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Sound,
				Method:    check.Naive,
			},
		},
		{
			// bar: s is only ever written into field .a of a local struct, and .a is never read,
			// so there is no flow from s to anything. This specifically exercises
			// field-sensitivity: a field-insensitive analysis would (incorrectly) find a flow from
			// s to the return, since the struct's other fields are returned.
			pkg:   pkg,
			name:  "bar",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name:      pkg + ".bar",
				Want:      summaries.DetailedSummary{},
				Soundness: check.Sound,
				Method:    check.Naive,
			},
		},
		{
			// zoo(c contents) string { return fooTop(c.a) + c.b }: fields .a and .b both flow to
			// the return (through and around the fooTop call, respectively), but .c does not.
			// The naive summary reports these as separate, field-sensitive flows.
			pkg:   pkg,
			name:  "zoo",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".zoo",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".a"}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".b"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".a"}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".b"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Sound,
				Method:    check.Naive,
			},
		},
		{
			// Same function as above, but the checked summary under-claims by omitting the
			// c.b -> return flow. This makes it unsound, and Got shows the actual naive summary
			// (including the missing flow) that was computed and compared against.
			pkg:   pkg,
			name:  "zoo",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".zoo",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".a"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".a"}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".b"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
				Method:    check.Naive,
			},
		},
		{
			// globalRoundTrip(s) writes s into a global and reads it back via a different
			// function, so the only path from s to the return goes through the global. This
			// checks that the naive visitor's global write -> read jump discovers the flow
			// instead of silently dropping it. Both writeGlobal and readGlobal are reachable from
			// globalRoundTrip's own call tree, so this is fully modeled and reported as sound.
			pkg:   pkg,
			name:  "globalRoundTrip",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".globalRoundTrip",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Sound,
				Method:    check.Naive,
			},
		},
		{
			// globalEscape(s) writes s into a global whose only read (in readEscapeGlobal) is not
			// reachable from globalEscape's own call tree (readEscapeGlobal is only called from
			// main, independently). The naive visitor cannot follow that read, so it must record
			// it as a potential source of unsoundness rather than silently missing it -- even
			// though the (correctly!) computed summary Got has no flows at all, since s never
			// reaches the return through any path the visitor can actually trace.
			pkg:   pkg,
			name:  "globalEscape",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name:      pkg + ".globalEscape",
				Want:      summaries.DetailedSummary{},
				Got:       summaries.DetailedSummary{},
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					CheckFeatures: check.UnsoundCheckFeatures{
						GlobalUsages: []token.Position{{}},
					},
				},
				Method: check.Naive,
			},
		},
		{
			// closureUnboundedDefers(s) calls a closure f that is only reached via free/bound
			// variable capture (BoundVarNode / a CallNode in ClosureTracing mode), never via a
			// regular CallNodeArg. f has its own unbounded defer stack, distinct from
			// closureUnboundedDefers' own body, so this regression test only passes if the
			// visitor records unsoundness for functions entered through closure capture, not just
			// through direct calls.
			pkg:   pkg,
			name:  "closureUnboundedDefers",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".closureUnboundedDefers",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ArgumentSNode{Name: "s", Index: 0},
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ArgumentSNode{Name: "s", Index: 0},
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					DataflowFeatures: check.UnsoundDataflowFeatures{
						HasUnboundedDefers: true,
					},
				},
				Method: check.Naive,
			},
		},
		{
			// globalRoundTripUnboundedDefers(s) writes s into a global and reads it back via
			// readGlobalUnboundedDefers, which is only reached through the global write->read
			// jump (not via any Call node) and has its own unbounded defer stack. This regression
			// test only passes if the visitor records unsoundness for functions entered through
			// the global jump, not just through direct calls.
			pkg:   pkg,
			name:  "globalRoundTripUnboundedDefers",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".globalRoundTripUnboundedDefers",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					DataflowFeatures: check.UnsoundDataflowFeatures{
						HasUnboundedDefers: true,
					},
				},
				Method: check.Naive,
			},
		},
		{
			// plainRecoverGap(s) calls plainRecoverCallee, which calls recover() from within a
			// deferred closure -- the idiomatic (and virtually universal) way recover() is used
			// in Go: `defer func() { recover() }()`. The recover() call therefore lives in an
			// anonymous function nested one level inside plainRecoverCallee, not in
			// plainRecoverCallee's own instructions. This regression test only passes if
			// recover() detection recurses into a function's anonymous (deferred) closures rather
			// than only scanning the function's own instructions.
			pkg:   pkg,
			name:  "plainRecoverGap",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".plainRecoverGap",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					DataflowFeatures: check.UnsoundDataflowFeatures{
						RecoverUsages: []token.Position{{}},
					},
				},
				Method: check.Naive,
			},
		},
		{
			// sourceGap calls Source() and Sink(), taint entry points per config.yaml.
			pkg:   pkg,
			name:  "sourceGap",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".sourceGap",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					CheckFeatures: check.UnsoundCheckFeatures{
						EntryPointUsages: []token.Position{{}, {}},
					},
				},
				Method: check.Naive,
			},
		},
		{
			// inner's free variable x is bound to a value that is itself a free variable of
			// outer. The naive visitor resolves this through nested MakeClosure/
			// ReferringMakeClosures, so checking nestedClosureNonLocal should be sound.
			pkg:   pkg,
			name:  "nestedClosureNonLocal",
			typ:   functionSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: pkg + ".nestedClosureNonLocal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
							summaries.ArgumentSNode{Name: "y", Index: 1},
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "x", Index: 0}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
							summaries.ArgumentSNode{Name: "y", Index: 1},
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Sound,
				Method:    check.Naive,
			},
		},
	}

	for _, tc := range tests {
		name := fmt.Sprintf("%s.%s_%s", tc.pkg, tc.name, tc.want.Soundness)
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
			name: "appendSliceLinkedList",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".appendSliceLinkedList",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "n", Index: 1}: {
							summaries.ArgumentSNode{Name: "head", Index: 0, ObjectPath: ".next"},
						},
						// NOTE To test redundant summary flows
						summaries.ArgumentSNode{Name: "n", Index: 1, ObjectPath: ".head"}: {
							summaries.ArgumentSNode{Name: "head", Index: 0, ObjectPath: ".next"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{},
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		// Same function, more general summary: types is sufficient
		{
			pkg:  pkg,
			name: "appendSliceLinkedList",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".appendSliceLinkedList",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "n", Index: 1}: {
							summaries.ArgumentSNode{Name: "head", Index: 0},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Types,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		// Same function, most general summary
		{
			pkg:  pkg,
			name: "appendSliceLinkedList",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".appendSliceLinkedList",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "n", Index: 1}: {
							summaries.ArgumentSNode{Name: "head", Index: 0},
						},
						summaries.ArgumentSNode{Name: "head", Index: 0}: {
							summaries.ArgumentSNode{Name: "n", Index: 1},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.General,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "appendSliceLinkedList",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".appendSliceLinkedList",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "n", Index: 1}: {
							summaries.ArgumentSNode{Name: "head", Index: 0, ObjectPath: ".value"},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "n", Index: 1},
							To:   summaries.ArgumentSNode{Name: "head", Index: 0, ObjectPath: ".next"},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
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
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Types,
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
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{},
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "threeArgInterFields",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".threeArgInterFields",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"}: {
							summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
							summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
						summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"}: {
							summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".addPairFirst",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"}: {
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"}: {
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
								},
							},
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{},
							},
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "threeArgInterFieldsDiffCallees",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".threeArgInterFieldsDiffCallees",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"}: {
							summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
							summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
						summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"}: {
							summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"},
							summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
						summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"}: {
							summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
						summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"}: {
							summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".addPairFirst",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"}: {
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"}: {
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
								},
							},
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{},
							},
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
					{
						{
							Name: pkg + ".addPairSecond",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"}: {
										summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"}: {
										summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
								},
							},
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{},
							},
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			pkg:  pkg,
			name: "threeArgInterTree",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".threeArgInterTree",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".left.left"}: {
							summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".left.right"},
						},
						summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".right.right"}: {
							summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".right.left"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{},
				},
				Method:        check.Recursive,
				CalleeResults: nil,
			},
		},
	}

	for _, tc := range tests {
		if tc.name == "threeArgInterTree" {
			t.Skipf("skipping due to false-positives in static analyses")
		}
		name := fmt.Sprintf("%s.%s_%s", tc.pkg, tc.name, tc.want.Soundness)
		t.Run(name, func(t *testing.T) { checkSoundness(t, tc, state) })
	}
}

func TestCheckSummary_Stdlib(t *testing.T) {
	t.Skip("skipping for now")

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
				Soundness: check.Sound,
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
				Soundness: check.Sound,
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
				Soundness: check.Soundy,
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
				// 			Soundness: check.Sound,
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
				// 			Soundness: check.Sound,
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
				// 			Soundness: check.Sound,
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
				// 			Soundness: check.Sound,
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
				// 						Soundness: check.Sound,
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
				// 						Soundness: check.Sound,
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
				// 						Soundness: check.Sound,
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
				// 			Soundness: check.Sound,
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
				// 						Soundness: check.Sound,
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
				// 						Soundness: check.Sound,
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
				// 						Soundness: check.Sound,
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
		name := fmt.Sprintf("%s.%s_%s", tc.pkg, tc.name, tc.want.Soundness)
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
	pkg   string
	name  string
	typ   summaryType
	naive bool
	want  check.SoundnessResult
}

func checkSoundness(t *testing.T, tc tcCheck, state *check.State) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	got, _, err = check.CheckSummary(ctx, state, summary, specs, tc.naive)
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
	if want.Name != got.Name {
		// This is an invariant that should be maintained by the test so panic instead of t.Fatal.
		panic(fmt.Errorf("function name mismatch: want %s, got %s", want.Name, got.Name))
	}

	if want.Want.String() != got.Want.String() {
		t.Errorf(
			"want summary mismatch for function %s: want %s, got %s", want.Name, want.Want, got.Want)
		return
	}

	if want.Got.String() != got.Got.String() {
		t.Errorf(
			"got (naive) summary mismatch for function %s: want %s, got %s", want.Name, want.Got, got.Got)
		return
	}

	if want.Soundness != got.Soundness {
		t.Errorf(
			"soundness mismatch for function %s: want %v, got %v\n",
			want.Name, want.Soundness, got.Soundness)
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

	// Positions are not compared exactly (they're brittle: absolute filenames aren't portable
	// across checkouts, and line/column shift whenever the testdata file is edited). Only the
	// count of each feature category is compared.
	wantCF, gotCF := want.Unsoundness.CheckFeatures, got.Unsoundness.CheckFeatures
	if len(wantCF.GlobalUsages) != len(gotCF.GlobalUsages) ||
		len(wantCF.UnsafeUsages) != len(gotCF.UnsafeUsages) ||
		len(wantCF.ReflectUsages) != len(gotCF.ReflectUsages) ||
		len(wantCF.NonLocalBoundLabelUsages) != len(gotCF.NonLocalBoundLabelUsages) ||
		len(wantCF.EntryPointUsages) != len(gotCF.EntryPointUsages) ||
		wantCF.TimedOut != gotCF.TimedOut {
		t.Errorf(
			"check features mismatch for function %s: want %+v, got %+v", want.Name, wantCF, gotCF)
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
