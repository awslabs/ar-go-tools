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
	"os"
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
	state, err := result.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to load state: %s", err)
	}
	check.InitializeState(state)

	tests := []struct {
		name  string
		wants []checkRes
	}{
		{
			name: "singleArgIntraOut",
			wants: []checkRes{
				{
					via:  check.General,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Types,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Naive,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
			},
		},
		{
			name: "singleArgInterNone",
			wants: []checkRes{
				{
					via:  check.General,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Types,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Naive,
					desc: []string{},
				},
			},
		},
		{
			name: "twoArgIntraInout",
			wants: []checkRes{
				{
					via: check.General,
					desc: []string{
						`{"from": "!arg <x>", "to": "!arg <y>"}`,
						`{"from": "!arg <y>", "to": "!arg <x>"}`,
					},
				},
				{
					via: check.Types,
					desc: []string{
						`{"from": "!arg <x>", "to": "!arg <y>"}`,
						`{"from": "!arg <y>", "to": "!arg <x>"}`,
					},
				},
				{
					via:  check.Naive,
					desc: []string{`{"from": "!arg <x>", "to": "!arg <y>"}`},
				},
			},
		},
		{
			name: "twoArgInterInout",
			wants: []checkRes{
				{
					via: check.General,
					desc: []string{
						`{"from": "!arg <x>", "to": "!arg <y>"}`,
						`{"from": "!arg <y>", "to": "!arg <x>"}`,
					},
				},
				{
					via: check.Types,
					desc: []string{
						`{"from": "!arg <x>", "to": "!arg <y>"}`,
						`{"from": "!arg <y>", "to": "!arg <x>"}`,
					},
				},
				{
					via:  check.Naive,
					desc: []string{`{"from": "!arg <x>", "to": "!arg <y>"}`},
				},
			},
		},
		{
			name: "singleArgIntraGlobal",
			wants: []checkRes{
				{
					via:  check.General,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Types,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Naive,
					desc: dataflow.ErrGlobal,
				},
			},
		},
		{
			name: "singleArgInterGlobal",
			wants: []checkRes{
				{
					via:  check.General,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Types,
					desc: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
				},
				{
					via:  check.Naive,
					desc: dataflow.ErrGlobal,
				},
			},
		},
		{
			name: "twoArgInterBool",
			wants: []checkRes{
				{
					via: check.General,
					desc: []string{
						`{"from": "!arg <x>", "to": "!ret 0"}`,
						`{"from": "!arg <x>", "to": "!arg <y>"}`,
						`{"from": "!arg <y>", "to": "!ret 0"}`,
						`{"from": "!arg <y>", "to": "!arg <x>"}`,
					},
				},
				{
					via: check.Types,
					desc: []string{
						`{"from": "!arg <x>", "to": "!ret 0"}`,
						`{"from": "!arg <y>", "to": "!ret 0"}`,
					},
				},
				{
					via: check.Naive,
					desc: []string{
						// `{"from": "!arg <x>", "to": "!ret 0"}`,
						`{"from": "!arg <y>", "to": "!ret 0"}`,
					},
				},
			},
		},
		{
			name: "twoArgInter",
			wants: []checkRes{
				{
					via: check.General,
					desc: []string{
						`{"from": "!arg <x>", "to": "!ret 0"}`,
						`{"from": "!arg <x>", "to": "!arg <y>"}`,
						`{"from": "!arg <y>", "to": "!ret 0"}`,
						`{"from": "!arg <y>", "to": "!arg <x>"}`,
					},
				},
				{
					via: check.Types,
					desc: []string{
						`{"from": "!arg <x>", "to": "!ret 0"}`,
						`{"from": "!arg <y>", "to": "!ret 0"}`,
					},
				},
				{
					via: check.Naive,
					desc: []string{
						`{"from": "!arg <x>", "to": "!ret 0"}`,
						`{"from": "!arg <y>", "to": "!ret 0"}`,
					},
				},
			},
		},
	}

	for _, tc := range tests {
		for _, want := range tc.wants {
			name := fmt.Sprintf("%s_%s", tc.name, want.via)
			t.Run(name, func(t *testing.T) {
				checkFlows(t, "github.com/awslabs/ar-go-tools/analysis/check/testdata/basic", tc.name, want, state)
			})
		}
	}
}

func TestCheckSummary_Stdlib(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	tests := []struct {
		name     string
		dir      string
		pkg      string
		function string
		wants    []checkRes
	}{
		{
			name:     "crypto/md5.Sum",
			pkg:      "crypto/md5",
			function: "Sum",
			wants: []checkRes{
				{
					via:  check.General,
					desc: []string{`{"from": "!arg <data>", "to": "!ret 0"}`},
				},
				{
					via:  check.Types,
					desc: []string{`{"from": "!arg <data>", "to": "!ret 0"}`},
				},
				{
					via:  check.Naive,
					desc: []string{`{"from": "!arg <data>", "to": "!ret 0"}`},
				},
			},
		},
		{
			name:     "sort.Ints",
			pkg:      "sort",
			function: "Ints",
			wants: []checkRes{
				{
					via:  check.General,
					desc: []string{},
				},
				{
					via:  check.Types,
					desc: []string{},
				},
				{
					via:  check.Naive,
					desc: []string{},
				},
			},
		},
	}

	for _, tc := range tests {
		dir := filepath.Join("./testdata", "stdlib", tc.pkg)
		lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{}).Value()
		if err != nil {
			t.Fatal(err)
		}
		setupConfig(lp)
		state, err := result.Bind(ptr.NewState(lp), dataflow.NewState).Value()
		if err != nil {
			t.Fatalf("failed to load state: %s", err)
		}

		for _, want := range tc.wants {
			name := fmt.Sprintf("%s_%s", tc.name, want.via)
			t.Run(name, func(t *testing.T) {
				check.InitializeState(state)
				checkFlows(t, tc.pkg, tc.function, want, state)
			})
		}
	}
}

func checkFlows(t *testing.T, pkg string, fn string, want checkRes, state *dataflow.State) {
	var tcWantErr error
	var tcWantFlows []string
	switch tcWant := want.desc.(type) {
	case []string:
		tcWantFlows = tcWant
	case error:
		tcWantErr = tcWant
	default:
		t.Fatalf("unexpected type: %T", want.desc)
	}
	str := fmt.Sprintf(`
{
	"package": "%s",
	"function": "%s",
	"flows": [%s]
}`, pkg, fn, strings.Join(tcWantFlows, ", "))
	var wantSummary summaries.FunctionFlowSummary
	if err := wantSummary.UnmarshalJSON([]byte(str)); err != nil {
		t.Fatalf("failed to unmarshal summary %s: %v", str, err)
	}
	res, err := check.CheckSummary(context.Background(), state, wantSummary, want.via)
	if !errors.Is(err, tcWantErr) {
		t.Errorf("unexpected check summary error:\n\twant %v,\n\tgot %v", tcWantErr, err)
		t.Logf("got graph:\n")
		res.GotGraph.PrettyPrint(true, os.Stdout, nil)
		return
	}
	wantFlows := wantSummary.Summary().Flows
	gotFlows := res.Got.Flows
	if !eqFlows(wantFlows, gotFlows) {
		t.Errorf("summary mismatch:\n\twant %v,\n\tgot %v\n", wantFlows, gotFlows)
		t.Logf("want:\n")
		dbgFlows(t, wantFlows)
		t.Logf("got:\n")
		dbgFlows(t, gotFlows)
		if res.GotGraph != nil {
			t.Logf("got graph:\n")
			res.GotGraph.PrettyPrint(true, os.Stdout, nil)
		}
	}
}

func eqFlows(want, got map[summaries.SummaryNode][]summaries.SummaryNode) bool {
	if len(want) == 0 && len(got) == 0 {
		return true
	}

	if len(want) != len(got) {
		return false
	}

	for wk, wvs := range want {
		found := false
		for gk, gvs := range got {
			if !eqNode(wk, gk) {
				continue
			}
			if !eqNodes(wvs, gvs) {
				return false
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}

	return true
}

func eqNodes(want, got []summaries.SummaryNode) bool {
	// need to sort the slices since EqualFunc compares elements in order
	slices.SortFunc(want, cmpNode)
	slices.SortFunc(got, cmpNode)
	return slices.EqualFunc(want, got, eqNode)
}

func cmpNode(x, y summaries.SummaryNode) int {
	return strings.Compare(x.String(), y.String())
}

func eqNode(want, got summaries.SummaryNode) bool {
	switch want := want.(type) {
	case summaries.ArgumentSNode:
		got, ok := got.(summaries.ArgumentSNode)
		if !ok {
			return false
		}
		// If want has a name, match by name; otherwise match by index
		if want.Name != "" {
			return want.Name == got.Name
		}
		return want.Index == got.Index
	case summaries.ReceiverSNode:
		got, ok := got.(summaries.ReceiverSNode)
		if !ok {
			return false
		}
		return want == got
	case summaries.ReturnSNode:
		got, ok := got.(summaries.ReturnSNode)
		if !ok {
			return false
		}
		return want.Index == got.Index
	default:
		panic(fmt.Errorf("unexpected summary node type: %T", want))
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

type checkRes struct {
	via  check.Method
	desc any // desc is the summary description (usually a slice of JSON strings)
}
