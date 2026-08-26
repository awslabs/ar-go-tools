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
	"errors"
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

// basicPkg is the import path of the basic testdata package.
const basicPkg = "github.com/awslabs/ar-go-tools/analysis/check/testdata/basic"

// invalidPkg is the import path of the invalid testdata package, which holds fixtures whose
// top-level checkSummary call is expected to be rejected outright.
const invalidPkg = "github.com/awslabs/ar-go-tools/analysis/check/testdata/invalid"

func TestCheckSummary_Basic(t *testing.T) {
	dir := filepath.Join("./testdata", "basic")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

	pkg := basicPkg
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
				Method:        check.Immutability,
				CalleeResults: nil,
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
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
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
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
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
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
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
				Method:        check.Immutability,
				CalleeResults: nil,
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
				Soundness:     check.Sound,
				Unsoundness:   check.Unsoundness{UnprovenMustNotFlows: nil},
				Method:        check.Immutability,
				CalleeResults: nil,
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
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".writeToClosed$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									// y -> x is absent, and correctly so: the closure is
									// `y = x; return x`, so nothing flows from y. It is excluded
									// because the encoding composes summary edges transitively --
									// y -> x together with x -> !ret 0 would realize y -> !ret 0,
									// which Want forbids -- and the free variables x and y are the
									// same vertices whether they act as the closure's inputs or its
									// outputs, so the composition is a real path in the flow graph.
									summaries.FreeVarSNode{Name: "x"}: {
										summaries.FreeVarSNode{Name: "y"},
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
							},
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			// See leakAcrossClosureCalls in the testdata: a regression test for composing a
			// callee's own summary edges. y -> x and x -> !ret 0 are both real flows of the
			// closure, and composed across the two calls they realize y -> !ret 0, which this Want
			// forbids. No inferred closure summary can contain both, so every candidate omits one
			// of the closure's real flows and the check correctly reports unsound. Treating the two
			// edges as independent instead yields a candidate the closure does satisfy, and the
			// summary is then reported sound even though y reaches the return value.
			pkg:  pkg,
			name: "leakAcrossClosureCalls",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".leakAcrossClosureCalls",
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
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						// Two co-optimal candidates, each satisfying 2 of the 4 possible
						// free-var/return may-flow edges. y -> !ret 0 must be false in both (it is
						// the flow being blocked), and of the remaining three, y -> x and
						// x -> !ret 0 are mutually exclusive because composing them realizes
						// y -> !ret 0. So each candidate keeps x -> y plus exactly one of them --
						// and therefore omits one of the closure's two real flows, which is why
						// neither can be proven sound.
						{
							Name: pkg + ".leakAcrossClosureCalls$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "x"}: {
										summaries.FreeVarSNode{Name: "y"},
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// y -> x is real (`x = y`), so this candidate genuinely does
									// not cover the closure. y -> !ret 0 does not hold within a
									// single call, since r is read before x is overwritten, but
									// Read cannot show that: y is read.
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
						{
							Name: pkg + ".leakAcrossClosureCalls$1",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.FreeVarSNode{Name: "x"}: {
										summaries.FreeVarSNode{Name: "y"},
									},
									summaries.FreeVarSNode{Name: "y"}: {
										summaries.FreeVarSNode{Name: "x"},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// x -> !ret 0 is real (`r := x; return r`), so this candidate
									// does not cover the closure either.
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
				Soundness: check.Soundy,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
					DataflowFeatures: check.UnsoundDataflowFeatures{
						NonLocalBoundLabelUsages: []token.Position{{}},
					},
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
				Soundness: check.Sound,
				Method:    check.Recursive,
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
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
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
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						// Only y -> x. The closure body is `*x = *x + *y`, so y is only ever
						// dereferenced for reading and nothing can flow into it; x -> y is
						// genuinely absent, and no inferred closure summary admits an edge into
						// the free variable y.
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
													summaries.FreeVarSNode{Name: "y"},
													summaries.ReturnSNode{Index: 0},
												},
											},
										},
										Soundness: check.Unsound,
										Unsoundness: check.Unsoundness{
											UnprovenMustNotFlows: []check.Flow{
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
		{
			// See coarsenedOutParam in the testdata: out is both an input and an output of the
			// function, named as a whole by the summary while its fields are written. The must-not-flows
			// against it are therefore stated at out as a whole.
			pkg:  pkg,
			name: "coarsenedOutParam",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".coarsenedOutParam",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".A"}: {
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".B"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						// Both real: joinSlots mixes a and b into both fields of its result, and the
						// body writes those into out.A/out.B. Stated against out as a whole, which is
						// how the summary names it.
						{
							From: summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".A"},
							To:   summaries.ArgumentSNode{Name: "out", Index: 1},
						},
						{
							From: summaries.ArgumentSNode{Name: "src", Index: 0, ObjectPath: ".B"},
							To:   summaries.ArgumentSNode{Name: "out", Index: 1},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							// Empty: any flow from a or b into the result would realize src -> out, so
							// every edge has to be false. joinSlots really does route both inputs into
							// both result fields, so it cannot satisfy that.
							//
							// Stated at depth 1 on the return because the caller reads r.A and r.B, so
							// that is the bound it demands of this callee. All four are real.
							Name:      pkg + ".joinSlots",
							Want:      summaries.DetailedSummary{},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.ArgumentSNode{Name: "a", Index: 0},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".A"},
									},
									{
										From: summaries.ArgumentSNode{Name: "a", Index: 0},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".B"},
									},
									{
										From: summaries.ArgumentSNode{Name: "b", Index: 1},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".A"},
									},
									{
										From: summaries.ArgumentSNode{Name: "b", Index: 1},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".B"},
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
			// negateInt is `return -x`. x really does reach the return value, via an arithmetic UnOp
			// rather than a dereference, so the read analysis must count that as reading x.
			pkg:  pkg,
			name: "negateInt",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name:      pkg + ".negateInt",
				Want:      summaries.DetailedSummary{},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "x", Index: 0},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// toAny is `return x` boxed into an interface, so x reaches the return value through a
			// MakeInterface.
			pkg:  pkg,
			name: "toAny",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name:      pkg + ".toAny",
				Want:      summaries.DetailedSummary{},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "x", Index: 0},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// multiFieldMethod's real behavior writes into "out" too, but Want only declares
			// flows into !ret 0, so every real flow into "out" (from the receiver's fields and
			// argX/Y/Z) is a genuine unproven must-not-flow. Each of the 4 receiver fields must be
			// distinguishable in the result (regression test: newSummaryNode used to always
			// return a bare ReceiverSNode{} with no ObjectPath, collapsing all 4 receiver-field-
			// sourced flows into indistinguishable duplicate entries).
			//
			// Flows into the receiver itself (and out -> !ret 0) are NOT unproven: the callee
			// multiFieldHelper is unsound only because it may leak its inputs to its own return
			// value, and multiFieldMethod only routes that return value into its own return (not
			// into the receiver or back out of "out"), so those must-not-flows remain proven even
			// though multiFieldHelper itself is unsound (see unprovenFlowsAfterCalleeCheck).
			pkg:      pkg,
			name:     "multiFieldMethod",
			receiver: "*multiFieldReceiver",
			typ:      methodSummary,
			want: check.SoundnessResult{
				Name: "(*" + pkg + ".multiFieldReceiver).multiFieldMethod",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ReceiverSNode{ObjectPath: ".fieldA"}:  {summaries.ReturnSNode{Index: 0}},
						summaries.ReceiverSNode{ObjectPath: ".fieldB"}:  {summaries.ReturnSNode{Index: 0}},
						summaries.ReceiverSNode{ObjectPath: ".fieldC"}:  {summaries.ReturnSNode{Index: 0}},
						summaries.ReceiverSNode{ObjectPath: ".fieldD"}:  {summaries.ReturnSNode{Index: 0}},
						summaries.ArgumentSNode{Name: "argX", Index: 0}: {summaries.ReturnSNode{Index: 0}},
						summaries.ArgumentSNode{Name: "argY", Index: 1}: {summaries.ReturnSNode{Index: 0}},
						summaries.ArgumentSNode{Name: "argZ", Index: 2}: {summaries.ReturnSNode{Index: 0}},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						// NOTE Only X -> out remains unproven: multiFieldHelper's return value is
						// written into out.fieldA/out.fieldB in the real code
						// (out.fieldA = res.outA), so this flow is real and correctly stays
						// unproven. Flows into the receiver (X -> receiver, out -> receiver) and
						// out -> !ret 0 are pruned: multiFieldHelper's unsound leak only reaches
						// its own return value, which multiFieldMethod only routes to its own
						// return (not to the receiver or out), so those must-not-flows remain
						// proven even though multiFieldHelper itself is unsound. (See
						// unprovenFlowsAfterCalleeCheck.)
						{From: summaries.ReceiverSNode{ObjectPath: ".fieldA"}, To: summaries.ArgumentSNode{Name: "out", Index: 3}},
						{From: summaries.ReceiverSNode{ObjectPath: ".fieldB"}, To: summaries.ArgumentSNode{Name: "out", Index: 3}},
						{From: summaries.ReceiverSNode{ObjectPath: ".fieldC"}, To: summaries.ArgumentSNode{Name: "out", Index: 3}},
						{From: summaries.ReceiverSNode{ObjectPath: ".fieldD"}, To: summaries.ArgumentSNode{Name: "out", Index: 3}},
						{From: summaries.ArgumentSNode{Name: "argX", Index: 0}, To: summaries.ArgumentSNode{Name: "out", Index: 3}},
						{From: summaries.ArgumentSNode{Name: "argY", Index: 1}, To: summaries.ArgumentSNode{Name: "out", Index: 3}},
						{From: summaries.ArgumentSNode{Name: "argZ", Index: 2}, To: summaries.ArgumentSNode{Name: "out", Index: 3}},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".multiFieldHelper",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0}: multiFieldHelperLeaks,
									summaries.ArgumentSNode{Name: "b", Index: 1}: multiFieldHelperLeaks,
									summaries.ArgumentSNode{Name: "c", Index: 2}: multiFieldHelperLeaks,
									summaries.ArgumentSNode{Name: "d", Index: 3}: multiFieldHelperLeaks,
									summaries.ArgumentSNode{Name: "x", Index: 4}: multiFieldHelperLeaks,
									summaries.ArgumentSNode{Name: "y", Index: 5}: multiFieldHelperLeaks,
									summaries.ArgumentSNode{Name: "z", Index: 6}: multiFieldHelperLeaks,
								},
							},
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// Only outA and outB remain: those are the two fields
									// multiFieldMethod routes into "out", so they are excluded from
									// the inferred summary above and become must-not-flows here.
									// The checker cannot prove any of them absent, because the
									// "read" method only proves absence for an input that is never
									// read at all, and every argument is read on some branch.
									{From: summaries.ArgumentSNode{Name: "a", Index: 0}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outA"}},
									{From: summaries.ArgumentSNode{Name: "a", Index: 0}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outB"}},
									{From: summaries.ArgumentSNode{Name: "b", Index: 1}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outA"}},
									{From: summaries.ArgumentSNode{Name: "b", Index: 1}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outB"}},
									{From: summaries.ArgumentSNode{Name: "c", Index: 2}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outA"}},
									{From: summaries.ArgumentSNode{Name: "c", Index: 2}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outB"}},
									{From: summaries.ArgumentSNode{Name: "d", Index: 3}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outA"}},
									{From: summaries.ArgumentSNode{Name: "d", Index: 3}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outB"}},
									{From: summaries.ArgumentSNode{Name: "x", Index: 4}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outA"}},
									{From: summaries.ArgumentSNode{Name: "x", Index: 4}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outB"}},
									{From: summaries.ArgumentSNode{Name: "y", Index: 5}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outA"}},
									{From: summaries.ArgumentSNode{Name: "y", Index: 5}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outB"}},
									{From: summaries.ArgumentSNode{Name: "z", Index: 6}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outA"}},
									{From: summaries.ArgumentSNode{Name: "z", Index: 6}, To: summaries.ReturnSNode{Index: 0, ObjectPath: ".outB"}},
								},
							},
							Soundness:     check.Unsound,
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			// mixedCalleeSoundness is a regression test for pruning UnprovenMustNotFlows after
			// the Recursive method's callee soundness check: it calls two different callees on
			// disjoint inputs -- modify (unsound, see sharedMutation above) and add1 (sound). Want
			// only declares b -> !ret 0 (add1's real flow), so every other pairing among a, b,
			// shared, and !ret 0 starts out as a must-not-flow. Only shared <-> a survive: they
			// are the only pairings realizable through modify's unsound reverse leak
			// (!arg <s> -> !arg <val>). Every must-not-flow touching b is proven despite modify
			// being unsound, because b is never passed to modify and add1 (the only callee that
			// touches b) is itself sound.
			pkg:  pkg,
			name: "mixedCalleeSoundness",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".mixedCalleeSoundness",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "b", Index: 1}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 0},
							To:   summaries.ArgumentSNode{Name: "shared", Index: 2},
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
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0},
									},
								},
							},
							Soundness: check.Sound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: nil,
							},
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
					{
						{
							Name: pkg + ".modify",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "s", Index: 1}: {
										summaries.ArgumentSNode{Name: "val", Index: 0},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.ArgumentSNode{Name: "val", Index: 0},
										To:   summaries.ArgumentSNode{Name: "s", Index: 1},
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
			// callerOfWriteStructPtrWithExtra is a regression test for a graph-identity bug found
			// while trying to distinguish precise vs. blanket forcing in
			// unprovenFlowsAfterCalleeCheck: checkCalleeSummaries recursively calls checkSummary
			// to verify writeStructPtrWithExtra's inferred summary, and checkSummary
			// unconditionally builds a *new* dataflow.SummaryGraph for it, overwriting
			// s.FlowGraph.Summaries[writeStructPtrWithExtra] with a graph whose nodes are distinct
			// (pointer-wise) from the ones the caller's traces/unknownMayFlow were built with. An
			// earlier version of edgesForUnsoundCalleeFlows resolved against that clobbered global
			// map entry, silently matching zero edges (instead of an error) and therefore forcing
			// nothing -- which happened to still prune a -> b (mapping to x -> y), silently
			// masking that a -> b was, at the time, also a false-positive in its own right (a and
			// b share a NodeIDs() collision with writeStructPtr above, since fixed). The fix
			// resolves against the call site's own call.CalleeSummary instead, which is never
			// clobbered.
			//
			// Want declares only b -> a (x = y, the real accepted direction, via *x = *y).
			// a -> b is now correctly proven by Immutability (b/y is never written), along with
			// c -> b and a -> c (c/z is never aliased). a -> ret0, b -> ret0, c -> a, and c -> ret0
			// remain genuinely unproven: none are disprovable by Read on writeStructPtrWithExtra
			// itself.
			pkg:  pkg,
			name: "callerOfWriteStructPtrWithExtra",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".callerOfWriteStructPtrWithExtra",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
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
						{
							From: summaries.ArgumentSNode{Name: "c", Index: 2},
							To:   summaries.ArgumentSNode{Name: "a", Index: 0},
						},
						{
							From: summaries.ArgumentSNode{Name: "c", Index: 2},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					writeStructPtrWithExtraCandidates,
				},
			},
		},
		{
			// twoCallSitesOfWriteStructPtrWithExtra calls writeStructPtrWithExtra at two call
			// sites with disjoint arguments (mirroring sharedMutation's two-call-site pattern).
			// This exercises calleeFlowKey (which gives both call sites one variable per summary
			// edge, so they cannot infer different summaries) together with
			// edgesForUnsoundCalleeFlows's per-call-site resolution via call.CalleeSummary: each call
			// site has its own distinct CalleeSummary graph object, so resolving the shared callee's
			// UnprovenMustNotFlows must correctly match edges at both sites.
			pkg:  pkg,
			name: "twoCallSitesOfWriteStructPtrWithExtra",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".twoCallSitesOfWriteStructPtrWithExtra",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "b", Index: 1}: {
							summaries.ArgumentSNode{Name: "a", Index: 0},
						},
						summaries.ArgumentSNode{Name: "q", Index: 3}: {
							summaries.ArgumentSNode{Name: "p", Index: 2},
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
						{
							From: summaries.ArgumentSNode{Name: "p", Index: 2},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							From: summaries.ArgumentSNode{Name: "q", Index: 3},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							From: summaries.ArgumentSNode{Name: "c", Index: 4},
							To:   summaries.ArgumentSNode{Name: "a", Index: 0},
						},
						{
							From: summaries.ArgumentSNode{Name: "c", Index: 4},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							From: summaries.ArgumentSNode{Name: "d", Index: 5},
							To:   summaries.ArgumentSNode{Name: "p", Index: 2},
						},
						{
							From: summaries.ArgumentSNode{Name: "d", Index: 5},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					writeStructPtrWithExtraCandidates,
				},
			},
		},
	}

	for _, tc := range tests {
		name := fmt.Sprintf("%s.%s_%s", tc.pkg, tc.name, tc.want.Soundness)
		t.Run(name, func(t *testing.T) { checkSoundness(t, tc, state) })
	}
}

// TestCheckSummary_ClosureRejected checks that checkSummary rejects a top-level target that is a
// closure with free variables, since the checkable summary format has no syntax for them.
func TestCheckSummary_ClosureRejected(t *testing.T) {
	dir := filepath.Join("./testdata", "basic")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

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

// TestCheckSummary_HigherOrderRejected checks that checkSummary reports soundy (not sound) for a
// top-level target that is higher-order: it has a parameter, receiver, or return value whose type
// resolves to a function, directly or through a struct field, since the checkable summary format
// has no syntax for function-typed inputs/outputs.
func TestCheckSummary_HigherOrderRejected(t *testing.T) {
	dir := filepath.Join("./testdata", "invalid")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

	specs := []dataflow.ScanningSpec{
		{
			IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
				return dataflow.IsNodeOfInterest(state.State, node)
			},
		},
	}

	for _, tc := range []struct {
		name            string
		summary         summaries.DetailedSummary
		wantHigherOrder check.HigherOrderVal
	}{
		{"higherOrderDirect", summaries.DetailedSummary{
			Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ArgumentSNode{Index: 1}: {summaries.ReturnSNode{Index: 0}},
			},
		}, check.HigherOrderVal{Path: "f", Type: "func()"}},
		{"higherOrderReturn", summaries.DetailedSummary{},
			check.HigherOrderVal{Path: "return value 0", Type: "func()"}},
		{"higherOrderField", summaries.DetailedSummary{
			Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ArgumentSNode{Index: 0, ObjectPath: ".V"}: {summaries.ReturnSNode{Index: 0}},
			},
		}, check.HigherOrderVal{Path: "b.H", Type: "func()"}},
		{"higherOrderMap", summaries.DetailedSummary{
			Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ArgumentSNode{Index: 0}: {summaries.ReturnSNode{Index: 0}},
			},
		}, check.HigherOrderVal{Path: "m", Type: "func()"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary := summaries.NewFunctionFlowSummary(invalidPkg, tc.name, tc.summary)
			results, _, err := check.CheckSummary(context.Background(), state, summary, specs, false)
			if err != nil {
				t.Fatalf("unexpected error checking higher-order function %s: %v", tc.name, err)
			}
			if len(results) == 0 {
				t.Fatalf("expected results for higher-order function %s, got none", tc.name)
			}
			if results[0].Soundness != check.Soundy {
				t.Fatalf("expected soundy for higher-order function %s, got %s", tc.name, results[0].Soundness)
			}
			hoVals := results[0].Unsoundness.CheckFeatures.HigherOrderVals
			if len(hoVals) == 0 {
				t.Fatalf("expected HigherOrderVals for %s, got none", tc.name)
			}
			if hoVals[0] != tc.wantHigherOrder {
				t.Fatalf("HigherOrderVals[0] for %s: got %+v, want %+v", tc.name, hoVals[0], tc.wantHigherOrder)
			}
		})
	}
}

// TestCheckSummary_InvalidSummaryStillFound checks that CheckSummary reports foundFunc=true (not
// false) for a reachable function whose summary ValidateSummary rejects, and that the returned
// SoundnessResult records the problem in Unsoundness.BadForm. This matters beyond CheckSummary's
// own contract: cmd/argot/check treats foundFunc=false as "no such function, nothing to
// report" and drops the result entirely (see checkOneSummaryWrapper), which would silently make
// an invalid summary vanish from check output instead of being reported as an error -- exactly
// the bug that motivated this test (a self-flow-only LLM-generated summary for a real, reachable
// function disappeared from experiment results instead of showing up as an error).
func TestCheckSummary_InvalidSummaryStillFound(t *testing.T) {
	dir := filepath.Join("./testdata", "basic")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

	// singleArgIntraOut is a real, reachable function (see TestCheckSummary_Basic); give it a
	// summary that is only a self-flow, which ValidateSummary must reject.
	summary := summaries.NewFunctionFlowSummary(basicPkg, "singleArgIntraOut",
		summaries.DetailedSummary{Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
			summaries.ArgumentSNode{Index: 0}: {summaries.ArgumentSNode{Index: 0}},
		}})
	specs := []dataflow.ScanningSpec{
		{
			IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
				return dataflow.IsNodeOfInterest(state.State, node)
			},
		},
	}
	results, found, err := check.CheckSummary(context.Background(), state, summary, specs, false)
	if err == nil {
		t.Fatal("expected an error for a self-flow-only summary, got nil")
	}
	if !found {
		t.Fatal("expected foundFunc=true: the function was found and is reachable, only its " +
			"summary is malformed -- callers must not treat this the same as \"no such function\"")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Soundness != check.Error {
		t.Errorf("expected Soundness = Error, got %v", results[0].Soundness)
	}
	if results[0].Unsoundness.BadForm == nil {
		t.Error("expected Unsoundness.BadForm to be set")
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
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

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
							summaries.ReturnSNode{Index: 0},
						},
						summaries.ArgumentSNode{Name: "y", Index: 1}: {
							summaries.ArgumentSNode{Name: "x", Index: 0},
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Sound,
				Method:    check.Naive,
			},
		},
		{
			// wrapper implements greeter; Greet only returns .msg, never .secret.
			pkg:   pkg,
			name:  "Greet",
			iface: "greeter",
			typ:   interfaceSummary,
			naive: true,
			want: check.SoundnessResult{
				Name: "(*" + pkg + ".wrapper).Greet",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ReceiverSNode{}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Got: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ReceiverSNode{}: {
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
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

	pkg := "github.com/awslabs/ar-go-tools/analysis/check/testdata/fields"
	tests := []tcCheck{
		{
			// FALSE POSITIVE, recorded rather than asserted to be correct. The summary is sound:
			// nothing flows from head.value to head.next, since the only write to a .next is a fresh
			// node whose value comes from n, and .value is never read.
			//
			// head is named at .next, so its bound reaches depth 1 and head.value -> head.next is a
			// deniable must-not-flow rather than an implicit flow. Discharging it needs head.value
			// proven unread, which the read analysis cannot do -- see the TODO in read.go's checkReads,
			// where a read whose label carries no path counts as reading every field.
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
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{
								Name: "head", Index: 0, ObjectPath: ".value"},
							To: summaries.ArgumentSNode{
								Name: "head", Index: 0, ObjectPath: ".next"},
						},
					},
				},
				Method:        check.Read,
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
							// Real: the fresh node assigned to current.next carries n in its value.
							From: summaries.ArgumentSNode{Name: "n", Index: 1},
							To:   summaries.ArgumentSNode{Name: "head", Index: 0, ObjectPath: ".next"},
						},
						{
							// The same false positive as the first appendSliceLinkedList case: head is
							// named at .value here, so its bound reaches depth 1 and this sibling flow
							// is deniable, but the read analysis cannot show head.value unread.
							From: summaries.ArgumentSNode{
								Name: "head", Index: 0, ObjectPath: ".value"},
							To: summaries.ArgumentSNode{
								Name: "head", Index: 0, ObjectPath: ".next"},
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
			// returnNestedByVal is `c.Dst.X = n; return c.Src`, so c.Src.X really does reach the
			// return value's .X. Nothing in the body addresses X under Src -- the return copies the
			// whole nested struct -- and c is by value, so its spill slot does not escape and the
			// pointer analysis has nothing to say about it. Both of the other read matchers
			// therefore find nothing, and only matchesWholeValueRead's prefix rule keeps this real
			// flow unproven instead of "proving" it absent.
			pkg:  pkg,
			name: "returnNestedByVal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".returnNestedByVal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src.X"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst.X"},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							// Not real -- `return c.Src` does not return Dst -- but c is a by-value
							// struct with no points-to information, so it is tracked
							// field-insensitively: reading any of it counts as reading all of it.
							//
							// Stated at .Dst.X because the summary names .Dst.X, so c's bound descends
							// on the Dst branch and .Dst.X is the access path enumerated there.
							From: summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst.X"},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							// Real: `return c.Src` copies the whole nested struct, including X.
							From: summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src.X"},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							// Not real, but n is read by `c.Dst.X = n`, so Read cannot rule it out.
							From: summaries.ArgumentSNode{Name: "n", Index: 1},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// returnArrayElemByVal is returnNestedByVal reached through an index instead of a field:
			// `a[1].Dst.X = n; return a[0]`, so a.Src.X really does reach the return value's .Src.X
			// (access paths do not track indices, so the two elements are one path). Nothing
			// addresses X under Src, and the array is by value so its spill slot does not escape.
			pkg:  pkg,
			name: "returnArrayElemByVal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".returnArrayElemByVal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Src.X"}: {
							summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Dst.X"},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							// Real: `return a[0]` copies the whole element, so its Dst comes out too.
							// Stated at .Dst.X because Want names a at .Dst.X, so a's bound descends on
							// the Dst branch and .Dst.X is the access path enumerated there.
							From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Dst.X"},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							// Real: `return a[0]` copies the whole element, including Src.X.
							From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Src.X"},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							// Not real, but n is read by `a[1].Dst.X = n`.
							From: summaries.ArgumentSNode{Name: "n", Index: 1},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// The soundness fix under test: siblingFieldViaCallee has a real flow s.A -> s.B, realized
			// inside writeSiblingField, alongside a second parameter t whose field-to-field flow makes
			// the summary field-sensitive. The summary below declares only t.Src -> t.Dst.
			//
			// The verdict turns on how a position the summary never names is read.
			pkg:  pkg,
			name: "siblingFieldViaCallee",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".siblingFieldViaCallee",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "s", Index: 0, ObjectPath: ".A"}: {
							summaries.ArgumentSNode{Name: "t", Index: 1, ObjectPath: ".Dst"},
						},
						summaries.ArgumentSNode{Name: "t", Index: 1, ObjectPath: ".Src"}: {
							summaries.ArgumentSNode{Name: "t", Index: 1, ObjectPath: ".Dst"},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "s", Index: 0, ObjectPath: ".A"},
							To:   summaries.ArgumentSNode{Name: "s", Index: 0, ObjectPath: ".B"},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							// The deduced summary for writeSiblingField declares s.B -> s, which does
							// not cover s.A -> s.B. Checked at the bound the caller entered it at --
							// where s.A and s.B are distinct -- the real flow s.A -> s.B is a
							// must-not-flow that no analysis discharges, so the callee is unsound and
							// the caller's must-not-flow stays unproven.
							Name: pkg + ".writeSiblingField",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "s", Index: 0, ObjectPath: ".B"}: {
										summaries.ArgumentSNode{Name: "s", Index: 0},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.ArgumentSNode{
											Name: "s", Index: 0, ObjectPath: ".A"},
										To: summaries.ArgumentSNode{
											Name: "s", Index: 0, ObjectPath: ".B"},
									},
								},
							},
							Method: check.Read,
						},
					},
				},
			},
		},
		{
			// Isolates output-side precision divergence: both call sites of addPairFirst receive the
			// same arguments, so their inputs have identical precision, and they differ only in how
			// deeply the result is read. calleeOutputDemand aggregates per output slot, so both sites
			// share one vocabulary rather than one naming the return whole and the other by field.
			pkg:  pkg,
			name: "sameArgDifferentOutputDepths",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".sameArgDifferentOutputDepths",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							// Real: y is returned whole as !ret 1 and comes from a.
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"},
							To:   summaries.ReturnSNode{Index: 1},
						},
						{
							// Not real -- addPairFirst reads only .First -- but a is a by-value Pair
							// at the call, tracked field-insensitively by Read.
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0},
						},
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 1},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							// One granularity throughout, unlike differentOutputDepths below: every
							// input is named at .First/.Second, with no bare !arg entry alongside.
							Name: pkg + ".addPairFirst",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								// Both endpoints at depth 1: the callee is checked at the bound its call
								// sites demanded, which reaches .First/.Second on the arguments and on
								// the return slot alike.
								//
								// None is a real flow (the return's .Second is never written, and the
								// .Second inputs are never read); they stay unproven because a and b are
								// by-value Pairs, which Read tracks field-insensitively.
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
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
			// differentOutputDepths calls addPairFirst twice, reading one result at .First and using
			// the other whole, so the two sites reach addPairFirst's arguments at different depths.
			// The callee summary below is nonetheless stated at a single granularity: the bare
			// parameters, which is the shallowest depth either site enters them at.
			//
			// This is the input-side counterpart of calleeOutputDemand. A callee's summary is shared
			// by all of its call sites, and calleeFlowKey names a summary edge partly by its access
			// path, so two granularities for one parameter would be two unrelated maxsat variables and
			// the reported summary would be the union of both -- more general than either site's model
			// justified. calleeInputNames collapses them to one; see its comment for why the
			// shallowest depth is both the only realizable choice and the safe one.
			pkg:  pkg,
			name: "differentOutputDepths",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".differentOutputDepths",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							// Real: y is returned as !ret 1 and comes from b.
							From: summaries.ArgumentSNode{Name: "b", Index: 2},
							To:   summaries.ReturnSNode{Index: 1},
						},
						{
							// Not real -- addPairFirst reads only .First fields -- but a is a
							// by-value Pair, tracked field-insensitively by Read.
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".addPairFirst",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									// One granularity, despite the two call sites reading the results
									// at different depths: the encoding names each parameter at the
									// shallowest depth any site enters it at, which here is the bare
									// parameter because one site uses its result whole.
									summaries.ArgumentSNode{Name: "a", Index: 0}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								// Stated at depth 1 because the callee is checked at the bound its call
								// sites demanded, not at the coarse one its own inferred summary is
								// named in. a.First -> ret.First and b.First -> ret.First are real
								// (`b.First = a.First + b.First; return Pair{First: b.First}`); the
								// rest are the by-value Pair imprecision -- a and b have no points-to
								// information, so reading any of one counts as reading all of it, and
								// ret.Second is never written but cannot be shown immutable.
								UnprovenMustNotFlows: []check.Flow{
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "a", Index: 0, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".First"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{
											Name: "b", Index: 1, ObjectPath: ".Second"},
										To: summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
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
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						// All eight follow from addPairFirst being unsound, and none is a real flow.
						// Its a and b are by-value Pairs with no points-to information, so Read
						// tracks them field-insensitively: reading a.First counts as reading all of
						// a, so a.Second and b.Second can no longer be proven unread and every
						// must-not-flow out of them stays open. The "no" flows are still proven --
						// addPairFirst never touches it at all.
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
						},
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
						{
							From: summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
						{
							From: summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"},
							To:   summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
						},
						{
							From: summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
						{
							From: summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".addPairFirst",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									// addPairFirst is `b.First = a.First + b.First; return
									// Pair{First: b.First}`, so both a.First and b.First really do
									// reach the return's .First.
									//
									// Only .First of the return value may be leaked into: the
									// parent routes y.Second straight into its own (!ret 0).Second,
									// a must-not-flow for every input, so every
									// -> (!ret 0).Second edge must be false. Telling the two halves
									// of the return value apart is what calleeOutputPaths makes
									// possible -- the parent reads x.First/y.First and y.Second, so
									// the return value is represented at depth 1 instead of as one
									// opaque value. Collapsed to a single output, b.First -> ret
									// would also imply b.First -> (!ret 0).Second and could not be
									// asserted at all, which is why it used to be missing here
									// despite being a real flow.
									//
									// "no" stays field-insensitive: the parent only forwards it to
									// the two calls and never reads a field of it, so
									// calleeOutputPaths finds no demand for depth (see the
									// same-value filter there).
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: addPairFirstUnproven,
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
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
						},
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
						{
							// Not a real flow, and the reason is flow-insensitivity rather than
							// anything about access paths. The route is
							// a.First -> x.First (addPairFirst, real) -> (*b).First at line 263
							// -> *b as addPairSecond's argument at line 262 -> y.First
							// (`return b`, real) -> (*b).Second at line 264.
							// The middle step goes backwards in time: the write to (*b).First
							// happens after the call that reads *b. A pointer-like parameter is one
							// node standing for the memory it points to across the whole function,
							// so "b on entry" and "b after the write" are the same vertex and the
							// two calls are not ordered relative to it.
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"},
							To:   summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"},
						},
						{
							From: summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
						{
							From: summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
						},
						{
							// Real: b.First reaches y.First through addPairSecond's `return b`,
							// and the parent writes y.First into (*b).Second.
							From: summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
							To:   summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".Second"},
						},
						{
							From: summaries.ArgumentSNode{Name: "b", Index: 2, ObjectPath: ".First"},
							To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
						},
					},
				},
				Method: check.Recursive,
				CalleeResults: [][]check.SoundnessResult{
					{
						{
							Name: pkg + ".addPairSecond",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									// addPairSecond is `b.Second = a.Second + b.Second; return b`,
									// so a.Second really does reach the return's .Second.
									//
									// Nothing reaches .First: the parent writes y.First into
									// (*b).Second, and every input's flow to b.Second other than
									// a.Second's and b.Second's own is a must-not-flow.
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: []check.Flow{
									// b.First -> (!ret 0).First is real: `return b` copies the whole
									// struct, so the caller's b.First comes back out in the return
									// value's .First.
									//
									// The other five are not real (the return's .First comes only
									// from b.First, and .Second only from a.Second/b.Second). They
									// stay unproven because a and b are by-value Pairs with no
									// points-to information, so Read tracks them
									// field-insensitively and cannot prove anything about an
									// individual field of either.
									{
										From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									{
										From: summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
									},
									{
										From: summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"},
										To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
								},
							},
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
					{
						{
							Name: pkg + ".addPairFirst",
							Want: summaries.DetailedSummary{
								Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
									// addPairFirst is `b.First = a.First + b.First; return
									// Pair{First: b.First}`, so both a.First and b.First really do
									// reach the return's .First. Nothing reaches .Second: the
									// parent writes x.Second into (*b).First and (!ret 0).Second,
									// and every input's flow to those is a must-not-flow except
									// a.First's and b.First's to b.First.
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
										summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
									},
									summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"}: {
										summaries.ArgumentSNode{Name: "no", Index: 2},
									},
								},
							},
							Soundness: check.Unsound,
							Unsoundness: check.Unsoundness{
								UnprovenMustNotFlows: addPairFirstUnproven,
							},
							Method:        check.Read,
							CalleeResults: nil,
						},
					},
				},
			},
		},
		{
			// Regression test: c.Src -> c.Dst has from.node == to.node (both are the parameter
			// c) but distinct access paths, so it must NOT be filtered out as a redundant
			// self-flow (see general.go's summaryFlows).
			pkg:  pkg,
			name: "copyFieldToOther",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".copyFieldToOther",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// Regression test: interaction between the self-flow filter and the
			// redundant-with-another-flow (subsumption) filter within the same summaryFlows
			// call. The declared summary has three flows:
			//   1. c.Src -> c.Dst        (real, distinct fields -- must survive)
			//   2. c.Src.X -> c.Dst.X    (finer version of #1 -- redundant via subsumption,
			//                             since a -> b implies a.f -> b.f; must be filtered)
			//   3. c.Src -> c.Src        (true self-flow on the whole Src field -- must be
			//                             filtered by the self-flow check, not by subsumption)
			// This checks that the self-flow filter (which only applies to flow #3, since it's
			// the only from.node==to.node pair) does not interfere with, or get bypassed by,
			// the separate subsumption filter applied to #1/#2 (a different node pairing).
			pkg:  pkg,
			name: "copyNestedFieldToOther",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".copyNestedFieldToOther",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst"},
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src"},
						},
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src.X"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst.X"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// Regression test for the access-path string-matching / field-attribution bugs:
			// "Body" is a string-prefix of "BodyStart", so path comparisons that used raw
			// string prefix/suffix checks previously misattributed writes/reads of one field to
			// the other. Three sub-bugs are exercised and fixed here:
			//   1. general.go's flowCovers / summaryFlows's subsumption filter no longer treats
			//      .Body as covering .BodyStart (fixed via subsumes comparing path segments
			//      instead of raw strings).
			//   2. read.go's checkReads no longer falls through from a definitive field
			//      mismatch (e.g. a *ssa.FieldAddr for &c.Body) into the generic points-to
			//      fallback, which would otherwise match any sibling field's label.
			//   3. valsReadFrom's *ssa.FieldAddr case no longer treats computing a field's
			//      address (&c.Body) as itself "reading" that field: c.Body/c.BodyStart's
			//      FieldAddr results here are only ever used as store *destinations*
			//      (c.Body = c.Src), never dereferenced for their prior value, so neither field
			//      is actually read by copySrcToBodyAndBodyStart -- the summary is Sound.
			pkg:  pkg,
			name: "copySrcToBodyAndBodyStart",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".copySrcToBodyAndBodyStart",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Body"},
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".BodyStart"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// Isolation test for checkWritesPtr (immutability method): writeBodyOnly writes only
			// c.Body, never c.BodyStart. A must-not-flow into c.BodyStart must be provable by
			// Immutability alone (c.BodyStart is never written), without being misattributed as
			// written because c.Body (a sibling field sharing a string prefix) was written.
			//
			// The flows into c.Body from c's other fields are declared so that the only must-not-flows
			// left are the ones into never-written fields. Immutability discharges those, so it is the
			// last analysis to run and Method pins that it did the work. Declaring them is
			// over-approximation, which a summary is free to do.
			pkg:  pkg,
			name: "writeBodyOnly",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".writeBodyOnly",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "v", Index: 1}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Body"},
						},
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Body"},
						},
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".BodyStart"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Body"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// True-positive counterpart to copySrcToBodyAndBodyStart: confirms
			// fieldAddrIsDereferenced still detects a genuine read through a field address
			// (p := &c.Val; return *p), rather than always reporting "not read" after the fix.
			// Want is empty (declares no flows), so c.Val -> !ret 0 (a real flow) must remain
			// unproven.
			pkg:  pkg,
			name: "readFieldViaPointer",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name:      pkg + ".readFieldViaPointer",
				Want:      summaries.DetailedSummary{},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							From: summaries.ArgumentSNode{Name: "c", Index: 0},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "readNestedFieldValue",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".readNestedFieldValue",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst.X"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							// .Src (not .Src.X): nothing in the checked summary names any path
							// under c.Src, so it is not on any relevant path and collapses to a
							// single path representing the whole field (see relevantPathsOfType)
							// instead of being enumerated leaf-by-leaf.
							From: summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src"},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			pkg:  pkg,
			name: "readNestedFieldValueByVal",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".readNestedFieldValueByVal",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst.X"}: {
							summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Soundness: check.Unsound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: []check.Flow{
						{
							// .Src (not .Src.X): see readNestedFieldValue above.
							From: summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src"},
							To:   summaries.ReturnSNode{Index: 0},
						},
					},
				},
				Method:        check.Read,
				CalleeResults: [][]check.SoundnessResult{},
			},
		},
		{
			// Isolation test for checkWritesPtr at a 2-segment path: writeNestedFieldOnly writes only
			// c.Src.X, so must-not-flows into c.Dst hold by immutability alone.
			//
			// As in writeBodyOnly, the flow into the written path from c's other enumerated path is
			// declared, so the must-not-flows that remain are only those into never-written memory and
			// Immutability is the last analysis to run.
			pkg:  pkg,
			name: "writeNestedFieldOnly",
			typ:  functionSummary,
			want: check.SoundnessResult{
				Name: pkg + ".writeNestedFieldOnly",
				Want: summaries.DetailedSummary{
					Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
						summaries.ArgumentSNode{Name: "v", Index: 1}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src.X"},
						},
						summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Dst"}: {
							summaries.ArgumentSNode{Name: "c", Index: 0, ObjectPath: ".Src.X"},
						},
					},
				},
				Soundness: check.Sound,
				Unsoundness: check.Unsoundness{
					UnprovenMustNotFlows: nil,
				},
				Method:        check.Immutability,
				CalleeResults: [][]check.SoundnessResult{},
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

// writeStructPtrWithExtraCandidates are the two co-optimal callee summaries inferred for
// writeStructPtrWithExtra (`*x = *y; return *z`), shared by its two caller test cases.
//
// The optimum satisfies 4 of the 6 possible arg-to-arg may-flow edges, not 5: the encoding composes
// a callee's summary edges transitively over the flow graph, so y -> x together with z -> y would
// realize z -> x -- c -> a in the caller, which the summary being checked forbids. Each candidate
// drops exactly one of those two edges, and neither dominates the other, so both are reported.
//
// In both, x -> !ret 0 is proven (x is only written, never read, so nothing of x can be returned)
// and z -> y is only available when y -> x is given up. y -> !ret 0, z -> x and z -> !ret 0 stay
// unproven: z is read and x is modified, so Read and Immutability cannot rule them out.
var writeStructPtrWithExtraCandidates = []check.SoundnessResult{
	{
		Name: basicPkg + ".writeStructPtrWithExtra",
		Want: summaries.DetailedSummary{
			Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ArgumentSNode{Name: "x", Index: 0}: {
					summaries.ArgumentSNode{Name: "y", Index: 1},
					summaries.ArgumentSNode{Name: "z", Index: 2},
				},
				summaries.ArgumentSNode{Name: "y", Index: 1}: {
					summaries.ArgumentSNode{Name: "x", Index: 0},
					summaries.ArgumentSNode{Name: "z", Index: 2},
				},
			},
		},
		Soundness: check.Unsound,
		Unsoundness: check.Unsoundness{
			UnprovenMustNotFlows: []check.Flow{
				{
					From: summaries.ArgumentSNode{Name: "y", Index: 1},
					To:   summaries.ReturnSNode{Index: 0},
				},
				{
					From: summaries.ArgumentSNode{Name: "z", Index: 2},
					To:   summaries.ArgumentSNode{Name: "x", Index: 0},
				},
				{
					From: summaries.ArgumentSNode{Name: "z", Index: 2},
					To:   summaries.ReturnSNode{Index: 0},
				},
			},
		},
		Method:        check.Read,
		CalleeResults: nil,
	},
	{
		Name: basicPkg + ".writeStructPtrWithExtra",
		Want: summaries.DetailedSummary{
			Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
				summaries.ArgumentSNode{Name: "x", Index: 0}: {
					summaries.ArgumentSNode{Name: "y", Index: 1},
					summaries.ArgumentSNode{Name: "z", Index: 2},
				},
				summaries.ArgumentSNode{Name: "y", Index: 1}: {
					summaries.ArgumentSNode{Name: "z", Index: 2},
				},
				summaries.ArgumentSNode{Name: "z", Index: 2}: {
					summaries.ArgumentSNode{Name: "y", Index: 1},
				},
			},
		},
		Soundness: check.Unsound,
		Unsoundness: check.Unsoundness{
			UnprovenMustNotFlows: []check.Flow{
				{
					From: summaries.ArgumentSNode{Name: "y", Index: 1},
					To:   summaries.ArgumentSNode{Name: "x", Index: 0},
				},
				{
					From: summaries.ArgumentSNode{Name: "y", Index: 1},
					To:   summaries.ReturnSNode{Index: 0},
				},
				{
					From: summaries.ArgumentSNode{Name: "z", Index: 2},
					To:   summaries.ArgumentSNode{Name: "x", Index: 0},
				},
				{
					From: summaries.ArgumentSNode{Name: "z", Index: 2},
					To:   summaries.ReturnSNode{Index: 0},
				},
			},
		},
		Method:        check.Read,
		CalleeResults: nil,
	},
}

// addPairFirstUnproven is the unproven must-not-flow set for addPairFirst's inferred summary, shared
// by the two callers that infer it.
//
// None of the six is a real flow: addPairFirst is `b.First = a.First + b.First; return
// Pair{First: b.First}`, so the return's .Second is never written and a.Second/b.Second are never
// used. They stay unproven because a and b are by-value Pairs with no points-to information, which
// Read tracks field-insensitively -- reading a.First counts as reading all of a, so nothing about
// a.Second can be proven. Flows out of "no" are still proven, since addPairFirst never touches it.
var addPairFirstUnproven = []check.Flow{
	{
		From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".First"},
		To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
	},
	{
		From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"},
		To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
	},
	{
		From: summaries.ArgumentSNode{Name: "a", Index: 0, ObjectPath: ".Second"},
		To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
	},
	{
		From: summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".First"},
		To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
	},
	{
		From: summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"},
		To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".First"},
	},
	{
		From: summaries.ArgumentSNode{Name: "b", Index: 1, ObjectPath: ".Second"},
		To:   summaries.ReturnSNode{Index: 0, ObjectPath: ".Second"},
	},
}

// multiFieldHelperLeaks are the fields of multiFieldHelper's return value that its inferred
// most-general callee summary may leak any input into.
//
// outA and outB are excluded, and that exclusion is the point of the test: multiFieldMethod writes
// res.outA/res.outB into "out", so a leak into either would realize a must-not-flow (input -> out),
// while the other five fields only reach multiFieldMethod's own return value, which Want allows.
// This distinction is only expressible because a callee output's access-path depth is discovered
// from how deeply the caller reads it (calleeOutputPaths); collapsed to a single field-insensitive
// output, no assignment can leak the five safe fields without also leaking outA/outB, and the
// inferred summary comes back empty.
var multiFieldHelperLeaks = []summaries.SummaryNode{
	summaries.ReturnSNode{Index: 0, ObjectPath: ".outC"},
	summaries.ReturnSNode{Index: 0, ObjectPath: ".outD"},
	summaries.ReturnSNode{Index: 0, ObjectPath: ".outX"},
	summaries.ReturnSNode{Index: 0, ObjectPath: ".outY"},
	summaries.ReturnSNode{Index: 0, ObjectPath: ".outZ"},
}

// TestCheckSummary_RedundantCallSiteSelfFlow reproduces a scaling bug where buildGraph treats an
// argument's own field flowing to a deeper field of the *same* argument, at an unsummarized call
// site, as a real, distinct fact to keep exploring -- when it actually carries no information
// about the callee at all (see requestUnmarshalLike's doc comment in testdata/fields/main.go).
// Left unfixed, this made checking real-world functions with wide, deeply-nested parameter types
// (e.g. aws-sdk-go's rest.Unmarshal on *request.Request) too slow to finish.
func TestCheckSummary_RedundantCallSiteSelfFlow(t *testing.T) {
	dir := filepath.Join("./testdata", "fields")
	lp, err := analysistest.LoadTest(
		testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

	pkg := "github.com/awslabs/ar-go-tools/analysis/check/testdata/fields"
	summary := summaries.NewFunctionFlowSummary(pkg, "requestUnmarshalLike", summaries.DetailedSummary{
		Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
			summaries.ArgumentSNode{Name: "r", Index: 0, ObjectPath: ".body"}: {
				summaries.ArgumentSNode{Name: "r", Index: 0, ObjectPath: ".err"},
			},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	specs := []dataflow.ScanningSpec{
		{
			IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
				return dataflow.IsNodeOfInterest(state.State, node)
			},
		},
	}
	// buildGraph's own traversal (inferring requestUnmarshalLike's callee summary) must complete
	// well within the context timeout: before the redundant-self-flow fix, the combinatorial
	// fan-out from r.safeBody -> (r as unmarshalLike's argument).safeBody caused this to blow up
	// (in the real aws-sdk-go case, hang indefinitely). This test only asserts that check
	// terminates promptly and produces a result; it does not assert anything about the precision
	// of checkReads/checkWritesPtr (a separate, pre-existing conservativeness in how a call
	// argument is treated as a "read" of the passed value, unrelated to this fix).
	got, _, err := check.CheckSummary(ctx, state, summary, specs, false)
	if err != nil {
		t.Fatalf("failed to check summary: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
}

// TestCheckSummary_CancelledContext asserts that cancelling the context surfaces as an error rather
// than as a soundness verdict.
//
// Must-not-flows are proven by absence of evidence, so an interrupted search must never be read as an
// absence: a timed-out summary reported Sound would be proven by a search that never finished.
func TestCheckSummary_CancelledContext(t *testing.T) {
	dir := filepath.Join("./testdata", "fields")
	lp, err := analysistest.LoadTest(
		testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	setupConfig(lp)
	ptrState, err := ptr.NewState(lp).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state := newCheckState(t, ptrState)

	pkg := "github.com/awslabs/ar-go-tools/analysis/check/testdata/fields"
	summary := summaries.NewFunctionFlowSummary(pkg, "differentOutputDepths", summaries.DetailedSummary{
		Flows: map[summaries.SummaryNode][]summaries.SummaryNode{
			summaries.ArgumentSNode{Name: "a", Index: 1, ObjectPath: ".First"}: {
				summaries.ReturnSNode{Index: 0},
			},
		},
	})
	specs := []dataflow.ScanningSpec{
		{
			IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
				return dataflow.IsNodeOfInterest(state.State, node)
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, _, err := check.CheckSummary(ctx, state, summary, specs, false)
	if err == nil {
		t.Fatal("expected an error from a cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected the error to wrap context.Canceled, got %v", err)
	}
	for _, r := range got {
		if r.Soundness == check.Sound {
			t.Errorf("cancelled check reported %s as Sound", r.Name)
		}
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
	interfaceSummary
)

type tcCheck struct {
	pkg      string
	name     string
	iface    string // interface name, only used when typ is interfaceSummary
	receiver string // receiver type name (e.g. "*Client"), only used when typ is methodSummary
	typ      summaryType
	naive    bool
	want     check.SoundnessResult
}

// newCheckState builds a fresh dataflow and check state over an already-computed pointer analysis
// state.
//
// Loading the program and running the pointer analysis is the expensive part and is safe to share,
// but the dataflow state must not be: it owns FlowGraph.Summaries, the cache of per-function
// summary graphs that checking a summary populates and mutates (a callee's summary graph is built
// on demand and stored there). Sharing one state across a table of subtests therefore leaks
// results between them -- a subtest can observe a callee summary graph left behind by whichever
// subtest ran earlier, which makes results depend on execution order. dataflow.NewState builds a
// fresh FlowGraph with empty maps on every call, so each subtest gets its own.
func newCheckState(t *testing.T, ptrState *ptr.State) *check.State {
	t.Helper()
	state, err := result.Bind(dataflow.NewState(ptrState), check.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	return state
}

func checkSoundness(t *testing.T, tc tcCheck, state *check.State) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var summary summaries.FrontendDataflowSummary
	switch tc.typ {
	case functionSummary:
		summary = summaries.NewFunctionFlowSummary(tc.pkg, tc.name, tc.want.Want)
	case methodSummary:
		summary = summaries.NewReceiverMethodFlowSummary(tc.pkg, tc.receiver, tc.name, tc.want.Want)
	case interfaceSummary:
		summary = summaries.NewIfaceMethodFlowSummary(tc.pkg, tc.iface, tc.name, tc.want.Want)
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
		len(wantCF.EntryPointUsages) != len(gotCF.EntryPointUsages) ||
		wantCF.TimedOut != gotCF.TimedOut {
		t.Errorf(
			"check features mismatch for function %s: want %+v, got %+v", want.Name, wantCF, gotCF)
		return
	}

	wantDF, gotDF := want.Unsoundness.DataflowFeatures, got.Unsoundness.DataflowFeatures
	if len(wantDF.RecoverUsages) != len(gotDF.RecoverUsages) ||
		len(wantDF.GoUsages) != len(gotDF.GoUsages) ||
		wantDF.HasUnboundedDefers != gotDF.HasUnboundedDefers ||
		len(wantDF.NonLocalBoundLabelUsages) != len(gotDF.NonLocalBoundLabelUsages) ||
		wantDF.TimedOut != gotDF.TimedOut ||
		len(wantDF.IntraTaintErrors) != len(gotDF.IntraTaintErrors) {
		t.Errorf(
			"dataflow features mismatch for function %s: want %+v, got %+v", want.Name, wantDF, gotDF)
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
	level := config.TraceLevel // change this as needed for debugging
	lp.Logger.Level = level
	lp.Logger.SupressWarn = false

	cfg := lp.Config
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false // change this as needed for debugging
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.CheckIgnoresUnsound = false
	cfg.LogLevel = int(level)
}
