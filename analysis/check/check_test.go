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
	"embed"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
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
		name string
		via  check.Method
		want any
	}{
		{
			name: "singleArgIntraOut",
			via:  check.Naive,
			want: []string{`{"from": "!arg <x>", "to": "!ret 0"}`},
		},
		{
			name: "singleArgInterNone",
			via:  check.Naive,
			want: []string{},
		},
		{
			name: "twoArgIntraInout",
			via:  check.Naive,
			want: []string{`{"from": "!arg <x>", "to": "!arg <y>"}`},
		},
		{
			name: "twoArgInterInout",
			via:  check.Naive,
			want: []string{`{"from": "!arg <x>", "to": "!arg <y>"}`},
		},
		{
			name: "singleArgIntraGlobal",
			via:  check.Naive,
			want: dataflow.ErrGlobal,
		},
		{
			name: "singleArgInterGlobal",
			via:  check.Naive,
			want: dataflow.ErrGlobal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var tcWantErr error
			var tcWantFlows []string
			switch tcWant := tc.want.(type) {
			case []string:
				tcWantFlows = tcWant
			case error:
				tcWantErr = tcWant
			}
			str := fmt.Sprintf(`
{
	"package": "github.com/awslabs/ar-go-tools/analysis/check/testdata/basic",
	"function": "%s",
	"flows": [%s]
}`, tc.name, strings.Join(tcWantFlows, ", "))
			var wantSummary summaries.FunctionFlowSummary
			if err := wantSummary.UnmarshalJSON([]byte(str)); err != nil {
				t.Fatalf("failed to unmarshal summary %s: %v", str, err)
			}
			res, err := check.CheckSummary(state, wantSummary, tc.via)
			if !errors.Is(err, tcWantErr) {
				t.Errorf("unexpected check summary error:\n\twant %v,\n\tgot %v", tcWantErr, err)
				t.Logf("got graph:\n")
				res.GotGraph.PrettyPrint(true, os.Stdout, nil)
				return
			}
			wantFlows := wantSummary.Summary().Flows
			gotFlows := res.Got.Flows
			if !maps.EqualFunc(wantFlows, gotFlows, cmpNodes) {
				t.Errorf("summary mismatch:\n\twant %v,\n\tgot %v\n", tcWantFlows, gotFlows)
				t.Logf("want:\n")
				dbgFlows(t, wantFlows)
				t.Logf("got:\n")
				dbgFlows(t, gotFlows)
				t.Logf("got graph:\n")
				res.GotGraph.PrettyPrint(true, os.Stdout, nil)
			}
		})
	}
}

func cmpNodes(want, got []summaries.SummaryNode) bool {
	return slices.EqualFunc(want, got, func(x, y summaries.SummaryNode) bool {
		if reflect.TypeOf(x) != reflect.TypeOf(y) {
			return false
		}

		switch x := x.(type) {
		case summaries.ArgumentSNode:
			y := y.(summaries.ArgumentSNode)
			return x.Name == y.Name || x.Index == y.Index
		case summaries.ReceiverSNode:
			y := y.(summaries.ReceiverSNode)
			return x == y
		case summaries.ReturnSNode:
			y := y.(summaries.ReturnSNode)
			return x.Index == y.Index
		default:
			panic(fmt.Errorf("unexpected summary node type: %T", x))
		}
	})
}

func dbgFlows(t *testing.T, flows map[summaries.SummaryNode][]summaries.SummaryNode) {
	for from, tos := range flows {
		t.Logf("\t%+v\n", from)
		for _, to := range tos {
			switch to := to.(type) {
			case summaries.ArgumentSNode:
				t.Logf("\t\tARG name: %v, index: %v, path: %v\n", to.Name, to.Index, to.ObjectPath)
			case summaries.ReturnSNode:
				t.Logf("\t\tRET index: %v, path: %v\n", to.Index, to.ObjectPath)
			default:
				t.Logf("unsupported summary node type: %T\n", to)
			}
		}
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
