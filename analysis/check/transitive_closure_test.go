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
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/check"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/ssa"
)

type testCase struct {
	name  string
	reach map[string][]string
}

func TestComputeTransitiveClosure(t *testing.T) {
	dir := filepath.Join("./testdata", "transitive_closure")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	setupConfig(lp)
	state, err := result.Bind(result.Bind(ptr.NewState(lp), dataflow.NewState), check.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	state.RunIntraProceduralPass(ctx, -1, dataflow.IntraAnalysisParams{
		ShouldBuildSummary: dataflow.ShouldBuildSummary,
	})
	state.FlowGraph.BuildGraph(true)
	testCases := []testCase{
		// fooTop: simple flow from argument to return
		{"fooTop", map[string][]string{"parameter s : string": {"return.0"}}},
		// bar: empty thanks to field sensitive analysis!
		{"bar", map[string][]string{}},
		// zoo: parameter flows to return
		{"zoo", map[string][]string{"parameter c : contents": {"return.0"}}},
		// copyString: parameter b flows to parameter a (b -> *a)
		{"copyString", map[string][]string{
			"parameter b : *string": {"parameter a : *string"},
			// A false positive because a and b are aliases
			"parameter a : *string": {"parameter b : *string"}},
		},
		// swapStrings: bidirectional flow between parameters
		{"swapStrings", map[string][]string{
			"parameter a : *string": {"parameter b : *string"},
			"parameter b : *string": {"parameter a : *string"},
		}},
		// conditionalCopy: parameter b flows to parameter a conditionally
		{"conditionalCopy", map[string][]string{"parameter b : *string": {"parameter a : *string"}}},
		// chainedCopy: transitive flow c -> b -> a
		{"chainedCopy", map[string][]string{
			"parameter c : *string": {"parameter a : *string", "parameter b : *string"},
			"parameter b : *string": {"parameter a : *string"},
		}},
		// transitiveViaHelper: b flows to a through helperCopy call
		{"transitiveViaHelper", map[string][]string{
			"parameter b : *string": {"parameter a : *string"},
			// Extra edge due to aliasing
			"parameter a : *string": {"parameter b : *string"}},
		},
		// transitiveChain: c flows to a through two copyString calls (c->b->a)
		{"transitiveChain", map[string][]string{
			"parameter c : *string": {"parameter a : *string", "parameter b : *string"},
			// Extra edges due to aliasing
			"parameter b : *string": {"parameter a : *string", "parameter c : *string"},
			"parameter a : *string": {"parameter b : *string"},
		}},
		// transitiveSwapChain: bidirectional flow through helperSwap->swapStrings
		{"transitiveSwapChain", map[string][]string{
			"parameter a : *string": {"parameter b : *string"},
			"parameter b : *string": {"parameter a : *string"},
		}},
		// transitiveReturn: parameter flows through helper to return value
		{"transitiveReturn", map[string][]string{"parameter s : *string": {"return.0"}}},
	}

	for test_case := range testCases {
		tc := testCases[test_case]
		t.Run(tc.name, func(t *testing.T) {
			f := findFunc(state, tc.name)
			if f == nil {
				t.Fatalf("failed to find function %s", tc.name)
			}
			cis, errC := check.ComputeClosedSummary(ctx, state.State, f)
			if errC != nil {
				t.Fatalf("failed to compute closed summary: %s", errC)
			}
			test(t, tc.reach, cis.Flows)
		})
	}
}

func simpleGraphNodeStr(node dataflow.GraphNode) string {
	switch tnode := node.(type) {
	case *dataflow.ParamNode:
		return tnode.SsaNode().String()
	case *dataflow.ReturnValNode:
		return "return." + strconv.Itoa(tnode.Index())
	default:
		return node.String()
	}
}

func test(t *testing.T, expected map[string][]string, actual map[dataflow.GraphNode][]dataflow.GraphNode) {
	actualSer := make(map[string][]string)
	for origin, dests := range actual {
		actualSer[simpleGraphNodeStr(origin)] = make([]string, len(dests))
		for i, dest := range dests {
			actualSer[simpleGraphNodeStr(origin)][i] = simpleGraphNodeStr(dest)
		}
	}
	for origin, dests := range expected {
		if _, ok := actualSer[origin]; !ok {
			t.Errorf("missing origin %s in actual", origin)
			break
		}
		for _, dest := range dests {
			if !funcutil.Contains(actualSer[origin], dest) {
				t.Errorf("%s: missing destination %s in actual", origin, dest)
			}
		}
	}
	for origin, dests := range actualSer {
		if _, ok := expected[origin]; !ok {
			t.Errorf("unexpected origin %s in actual", origin)
			break
		}
		for _, dest := range dests {
			if !funcutil.Contains(expected[origin], dest) {
				t.Errorf("%s unexpected destination %s in actual", origin, dest)
			}
		}
	}
}

func findFunc(s *check.State, name string) *ssa.Function {
	for f := range s.ReachableFunctions() {
		if strings.Contains(f.String(), name) {
			return f
		}
	}
	return nil
}
