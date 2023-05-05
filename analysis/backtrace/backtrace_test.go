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

package backtrace_test

import (
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/argot/analysis/backtrace"
	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/testutils"
	"github.com/awslabs/argot/internal/funcutil"
)

func TestAnalyze(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/backtrace")
	// Loading the program for testdata/src/backtrace/main.go
	program, cfg := testutils.LoadTest(t, dir, []string{})
	defer os.Remove(cfg.ReportsDir)

	res, err := backtrace.Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		matches []match
	}{
		{
			name: `trace to os/exec.Command arg 0 in main from os/exec.Command arg 0 in main`,
			// "(SA)call: os/exec.Command("ls":string, nil:[]string...) in main [#576.5]: @arg 0:"ls":string [#576.6]" at -
			matches: []match{
				{arg, argval{`"ls":string`, 0}, 0},
			},
		},
		{
			name: `trace to os/exec.Command arg 1 in main from os/exec.Command arg 1 in main`,
			// "(SA)call: os/exec.Command("ls":string, nil:[]string...) in main [#580.5]: @arg 1:nil:[]string [#580.7]" at -
			matches: []match{
				{arg, argval{`nil:[]string`, 1}, 0},
			},
		},
		{
			name: `trace to *os.Args in main from os/exec.Command arg 0 in main`,
			// "[#582.1] global:os.Args in *os.Args (read)" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:31:26
			// "(SA)call: os/exec.Command(t6, t8...) in main [#582.10]: @arg 0:t6 [#582.11]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:31:30
			matches: []match{
				{globalRead, `*os.Args`, 31},
				{arg, argval{nil, 0}, 31}, // nil indicates non-static arg
			},
		},
		{
			name: `trace to *os.Args in main from os/exec.Command arg 1 in main`,
			// "[#582.1] global:os.Args in *os.Args (read)" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:31:38
			// "(SA)call: os/exec.Command(t6, t8...) in main [#582.10]: @arg 1:t8 [#582.12]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:31:42
			matches: []match{
				{globalRead, `*os.Args`, 31},
				{arg, argval{nil, 1}, 31},
			},
		},
		{
			name: `trace to *os.Args in main from os/exec.Command arg 0 in runcmd`,
			// "[#581.2] global:os.Args in *os.Args (read)" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:43:22
			// "(SA)call: runcmd(t21, t23...) in main [#581.21]: @arg 0:t21 [#581.22]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:43:26
			// "[#576.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#576.3]: @arg 0:name [#576.4]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			matches: []match{
				{globalRead, `*os.Args`, 43},
				{arg, argval{nil, 0}, 43},
				{param, `parameter name : string`, 71},
				{arg, argval{`name`, 0}, 71},
			},
		},
		{
			name: `trace to *os.Args in main from os/exec.Command arg 1 in runcmd`,
			// "[#582.3] global:os.Args in *os.Args (read)" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:43:34
			// "(SA)call: runcmd(t21, t23...) in main [#582.21]: @arg 1:t23 [#582.23]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:43:38
			// "[#581.1] parameter args : []string of runcmd [1]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:26
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#581.3]: @arg 1:args [#581.5]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:26
			matches: []match{
				{globalRead, `*os.Args`, 43},
				{arg, argval{nil, 1}, 43},
				{param, `parameter args : []string`, 71},
				{arg, argval{`args`, 1}, 71},
			},
		},
		{
			name: `trace to runcmd("ls1") arg 0 in main from os/exec.Command arg 0 in runcmd`,
			// "(SA)call: runcmd("ls1":string, nil:[]string...) in main [#577.17]: @arg 0:"ls1":string [#577.16]" at -
			// "[#581.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#581.3]: @arg 0:name [#581.4]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			matches: []match{
				{arg, argval{`"ls1":string`, 0}, 0},
				{param, `parameter name : string`, 71},
				{arg, argval{`name`, 0}, 71},
			},
		},
		{
			name: `trace to runcmd("ls1") arg 1 in main from os/exec.Command arg 1 in runcmd`,
			// "(SA)call: runcmd("ls1":string, nil:[]string...) in main [#579.17]: @arg 1:nil:[]string [#579.17]" at -
			// "[#578.1] parameter args : []string of runcmd [1]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:26
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#578.3]: @arg 1:args [#578.5]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:26
			matches: []match{
				{arg, argval{`nil:[]string`, 1}, 0},
				{param, `parameter args : []string`, 71},
				{arg, argval{`args`, 1}, 71},
			},
		},
		{
			name: `trace to runcmd("ls2") arg 0 in main from os/exec.Command arg 0 in runcmd`,
			// "(SA)call: runcmd("ls2":string, nil:[]string...) in main [#580.18]: @arg 0:"ls2":string [#580.19]" at -
			// "[#582.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#582.3]: @arg 0:name [#582.4]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			matches: []match{
				{arg, argval{`"ls2":string`, 0}, 0},
				{param, `parameter name : string`, 71},
				{arg, argval{`name`, 0}, 71},
			},
		},
		{
			name: `trace to runcmd("ls2") arg 1 in main from os/exec.Command arg 1 in runcmd`,
			// "(SA)call: runcmd("ls2":string, nil:[]string...) in main [#580.18]: @arg 0:"ls2":string [#580.19]" at -
			// "[#582.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#582.3]: @arg 0:name [#582.4]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			matches: []match{
				{arg, argval{`nil:[]string`, 1}, 0},
				{param, `parameter args : []string`, 71},
				{arg, argval{`args`, 1}, 71},
			},
		},
		{
			name: `trace to runcmd(bar("ls3")) arg 0 in main from os/exec.Command arg 0 in runcmd`,
			// "[#581.26] @arg 0:"ls3":string in [#581.25] (SA)call: bar("ls3":string) in main " at -
			// "[#582.0] parameter x : string of bar [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:63:10
			// "[#582.3] @arg 0:x in [#582.2] (SA)call: baz(x) in bar " at /Volumes/workplace/argot/testdata/src/backtrace/main.go:63:10
			// "[#580.0] parameter x : string of baz [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:67:10
			// "[#580.1] baz.return" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:67:6
			// "[#582.2] (SA)call: baz(x) in bar" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:64:12
			// "[#582.1] bar.return" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:63:6
			// "[#581.25] (SA)call: bar("ls3":string) in main" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:49:12
			// "[#581.28] @arg 0:t28 in [#581.27] (SA)call: runcmd(t28, nil:[]string...) in main " at /Volumes/workplace/argot/testdata/src/backtrace/main.go:49:12
			// "[#583.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "[#583.4] @arg 0:name in [#583.3] (SA)call: os/exec.Command(name, args...) in runcmd " at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71
			matches: []match{
				{arg, argval{`"ls3":string`, 0}, 0},
				{param, `parameter x : string`, 63},
				{arg, argval{`x`, 0}, 63},
				{param, `parameter x : string`, 67},
				{ret, nil, 67},
				{call, `baz`, 64},
				{ret, nil, 63},
				{call, `bar`, 49},
				{arg, argval{nil, 0}, 49},
				{param, `parameter name : string`, 71},
				{arg, argval{nil, 0}, 71},
			},
		},
		{
			name: `trace to runcmd("ls4") arg 0 in foo from os/exec.Command arg 0 in runcmd`,
			// "(SA)call: runcmd("ls4":string, nil:[]string...) in foo [#579.1]: @arg 0:"ls4":string [#579.2]" at -
			// "[#577.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#577.3]: @arg 0:name [#577.4]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			matches: []match{
				{arg, argval{`"ls4":string`, 0}, 0},
				{param, `parameter name : string`, 71},
				{arg, argval{`name`, 0}, 71},
			},
		},
		{
			name: `trace to runcmd("ls4") arg 1 in foo from os/exec.Command arg 1 in runcmd`,
			// "(SA)call: runcmd("ls4":string, nil:[]string...) in foo [#577.1]: @arg 1:nil:[]string [#577.3]" at -
			// "[#578.1] parameter args : []string of runcmd [1]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:26
			// "(SA)call: os/exec.Command(name, args...) in runcmd [#578.3]: @arg 1:args [#578.5]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:26
			matches: []match{
				{arg, argval{`nil:[]string`, 1}, 0},
				{param, `parameter args : []string`, 71},
				{arg, argval{`args`, 1}, 71},
			},
		},
		{
			name: `trace to baz("hello1") arg 0 in runglobal from os/exec.Command arg 0 in runcmd`,
			// "[#579.3] @arg 0:"hello1":string in [#579.2] (SA)call: baz("hello1":string) in runglobal " at -
			// "[#584.0] parameter x : string of baz [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:67:10
			// "[#584.1] baz.return" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:67:6
			// "[#579.2] (SA)call: baz("hello1":string) in runglobal" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:81:14
			// "[#579.1] global:command-line-arguments.global in *global = t0 (write)" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:81:2
			// "[#583.4] global:command-line-arguments.global in *global (read)" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:89:9
			// "[#583.0] write.return" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:85:6
			// "[#579.4] (SA)call: write() in runglobal" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:82:14
			// "[#579.6] @arg 0:t1 in [#579.5] (SA)call: runcmd(t1, nil:[]string...) in runglobal " at /Volumes/workplace/argot/testdata/src/backtrace/main.go:82:14
			// "[#580.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "[#580.4] @arg 0:name in [#580.3] (SA)call: os/exec.Command(name, args...) in runcmd " at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			matches: []match{
				{arg, argval{`"hello1":string`, 0}, 0},
				{param, `parameter x : string`, 67},
				{ret, nil, 67},
				{call, `baz`, 81},
				{globalWrite, `*global`, 81},
				{globalRead, `*global`, 89},
				{ret, nil, 85},
				{call, `write`, 82},
				{arg, argval{nil, 0}, 82},
				{param, `parameter name : string`, 71},
				{arg, argval{nil, 0}, 71},
			},
		},
		{
			name: `trace to baz("hello2") arg 0 in runglobal from os/exec.Command arg 0 in runcmd`,
			// "[#583.6] @arg 0:"hello2":string in [#583.5] (SA)call: baz("hello2":string) in write " at -
			// "[#584.0] parameter x : string of baz [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:67:10
			// "[#584.1] baz.return" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:67:6
			// "[#583.5] (SA)call: baz("hello2":string) in write" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:87:15
			// "[#583.0] write.return" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:85:6
			// "[#579.4] (SA)call: write() in runglobal" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:82:14
			// "[#579.6] @arg 0:t1 in [#579.5] (SA)call: runcmd(t1, nil:[]string...) in runglobal " at /Volumes/workplace/argot/testdata/src/backtrace/main.go:82:14
			// "[#580.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			// "[#580.4] @arg 0:name in [#580.3] (SA)call: os/exec.Command(name, args...) in runcmd " at /Volumes/workplace/argot/testdata/src/backtrace/main.go:71:13
			matches: []match{
				{arg, argval{`"hello2":string`, 0}, 0},
				{param, `parameter x : string`, 67},
				{ret, nil, 67},
				{call, `baz`, 87},
				{ret, nil, 85},
				{call, `write`, 82},
				{arg, argval{nil, 0}, 82},
				{param, `parameter name : string`, 71},
				{arg, argval{nil, 0}, 71},
			},
		},
	}

	if len(res.Traces) < len(tests) {
		t.Fatalf("analysis did not find enough traces: want at least %d, got %d", len(tests), len(res.Traces))
	}

	t.Log("TRACES:")
	for _, trace := range res.Traces {
		t.Log(trace)
	}

	for _, test := range tests {
		test := test // needed for t.Parallel()
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if !funcutil.Exists(res.Traces, func(trace backtrace.Trace) bool {
				ok, err := matchTrace(trace, test.matches)
				_ = err
				// // NOTE commented out for debugging
				// if err != nil {
				// 	t.Errorf("failed match: %v in trace: %v", err, trace)
				// }

				return ok
			}) {
				t.Error("no match")
			}
		})
	}

	t.Run(`trace to bar("x") should not exist`, func(t *testing.T) {
		if funcutil.Exists(res.Traces, func(trace backtrace.Trace) bool {
			arg, ok := trace[0].GraphNode.(*dataflow.CallNodeArg)
			if !ok {
				return false
			}

			return arg.Value().Name() == `"x":string`
		}) {
			t.Errorf("incorrect trace")
		}
	})

	// TODO fix the false positives
	// if len(tests) != len(res.Traces) {
	// 	t.Errorf("test length mismatch: got %d, want %d", len(tests), len(res.Traces))
	// }

	// TODO incorrect trace: *os.Args in main.go:31 should not flow to call to runcmd:
	// need better context sensitivity for global read
	// This might be fine?
	//
	// "[#578.2] global:os.Args in *os.Args (read)" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:31:38
	// "(SA)call: runcmd(t21, t23...) in main [#578.21]: @arg 0:t21 [#578.22]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:43:26
	// "[#577.0] parameter name : string of runcmd [0]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:85:13
	// "(SA)call: os/exec.Command(name, args...) in runcmd [#577.3]: @arg 0:name [#577.4]" at /Volumes/workplace/argot/testdata/src/backtrace/main.go:85:13
}

func TestAnalyze_Closures(t *testing.T) {
	// This test uses the taint analysis' closures test file to ensure completeness.
	// The backtracepoints (entrypoints to the backwards analysis) are identical to the sinks in the taint analysis.
	// See the config.yaml file for details.

	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/taint/closures")
	// Loading the program for testdata/src/taint/closures/main.go
	program, cfg := testutils.LoadTest(t, dir, []string{"helpers.go"})
	defer os.Remove(cfg.ReportsDir)

	res, err := backtrace.Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		matches []match
	}{
		{
			name: `trace to source in example1 from sink arg 0 in example1`,
			// "[#471.0] source.return" at /Volumes/workplace/argot/testdata/src/taint/closures/helpers.go:23:6
			// "[#447.4] (SA)call: source() in example1" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:32:13
			// "[#447.6] @arg 0:t3 in [#447.5] (SA)call: t2(t3) in example1 " at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:32:13
			// "[#483.0] parameter a : string of example1$1 [0]" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:31:23
			// "[#483.5] @arg 0:a in [#483.4] (SA)call: wrap(a, t0, t1) in example1$1 " at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:31:23
			// "[#500.0] parameter a : string of wrap [0]" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:23:11
			// "[#500.6] @arg 1:t7 in [#500.4] (SA)call: fmt.Sprintf("%s%s%s":string, t7...) in wrap " at -
			// "[#519.1] parameter a : []any of Sprintf [1]" at /opt/homebrew/Cellar/go/1.20.1/libexec/src/fmt/print.go:237:29
			// "[#519.2] Sprintf.return" at /opt/homebrew/Cellar/go/1.20.1/libexec/src/fmt/print.go:237:6
			// "[#500.4] (SA)call: fmt.Sprintf("%s%s%s":string, t7...) in wrap" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:24:20
			// "[#500.3] wrap.return" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:23:6
			// "[#483.4] (SA)call: wrap(a, t0, t1) in example1$1" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:31:53
			// "[#483.3] example1$1.return" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:31:18
			// "[#447.5] (SA)call: t2(t3) in example1" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:33:19
			// "[#447.8] @arg 0:t7 in [#447.7] (SA)call: sink(t7...) in example1 " at -
			matches: []match{
				{ret, nil, 23},
				{call, `source`, 32},
				{arg, argval{nil, 0}, 32},
				{param, `parameter a : string`, 31},
				{arg, argval{nil, 0}, 31},
				{param, `parameter a : string`, 23},
				{arg, argval{nil, 1}, 0},
				{param, `parameter a : []any`, 237},
				{ret, nil, 237},
				{call, `Sprintf`, 24},
				{ret, nil, 23},
				{call, `wrap`, 31},
				{ret, nil, 31},
				{call, nil, 33},
				{arg, argval{nil, 0}, 0},
			},
		},
		{
			name: `trace to boundvar:new string(lparen) in example1 from sink arg 0 in example1`,
			// "[#515.2] boundvar:new string (lparen)" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:29:2
			// "[#505.1] freevar:lparen" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:29:2
			// "[#505.6] @arg 1:t0 in [#505.4] (SA)call: wrap(a, t0, t1) in example1$1 " at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:31:57
			// "[#492.1] parameter before : string of wrap [1]" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:23:21
			// "[#492.6] @arg 1:t7 in [#492.4] (SA)call: fmt.Sprintf("%s%s%s":string, t7...) in wrap " at -
			// "[#521.1] parameter a : []any of Sprintf [1]" at /opt/homebrew/Cellar/go/1.20.1/libexec/src/fmt/print.go:237:29
			// "[#521.2] Sprintf.return" at /opt/homebrew/Cellar/go/1.20.1/libexec/src/fmt/print.go:237:6
			// "[#492.4] (SA)call: fmt.Sprintf("%s%s%s":string, t7...) in wrap" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:24:20
			// "[#492.3] wrap.return" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:23:6
			// "[#505.4] (SA)call: wrap(a, t0, t1) in example1$1" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:31:53
			// "[#505.3] example1$1.return" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:31:18
			// "[#515.5] (SA)call: t2(t3) in example1" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:33:19
			// "[#515.8] @arg 0:t7 in [#515.7] (SA)call: sink(t7...) in example1 " at -
			matches: []match{
				// {boundvar, `new string (lparen)`, 29}, TODO figure out why boundvar isn't in the trace
				{freevar, `lparen`, 29},
				{arg, argval{nil, 1}, 31},
				{param, `parameter before : string`, 23},
				{arg, argval{nil, 1}, 0},
				{param, `parameter a : []any`, 237},
				{ret, nil, 237},
				{call, `Sprintf`, 24},
				{ret, nil, 23},
				{call, `wrap`, 31},
				{ret, nil, 31},
				{call, nil, 33},
				{arg, argval{nil, 0}, 0},
			},
		},
		{
			name: `trace to source.return in example6 from sink arg 0 in example6`,
			// "[#498.0] source.return" at /Volumes/workplace/argot/testdata/src/taint/closures/helpers.go:23:6
			// "[#515.7] (SA)call: source() in example6" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:118:12
			// "[#515.6] boundvar:new string (x)" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:113:2
			// "[#465.0] freevar:x" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:113:2
			// "[#465.3] boundvar:freevar x : *string" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:113:2
			// "[#465.2] closure:make closure example6$1$1 [x]" at -
			// "[#465.4] (SA)call: t0() in example6$1" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:116:13
			// "[#465.1] example6$1.return" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:114:8
			// "[#515.8] (SA)call: t7() in example6" at /Volumes/workplace/argot/testdata/src/taint/closures/main.go:119:9
			// "[#515.10] @arg 0:t12 in [#515.9] (SA)call: sink(t12...) in example6 " at -
			matches: []match{
				{ret, nil, 23},
				{call, `source`, 118},
				{boundvar, `new string (x)`, 113},
				{freevar, `x`, 113},
				{boundvar, `freevar x : *string`, 113},
				{closure, `make closure example6$1$1 [x]`, 0},
				{call, nil, 116},
				{ret, nil, 114},
				{call, nil, 119},
				{arg, argval{nil, 0}, 0},
			},
		},
	}

	if len(res.Traces) < len(tests) {
		t.Fatalf("analysis did not find enough traces: want at least %d, got %d", len(tests), len(res.Traces))
	}

	t.Log("TRACES:")
	for _, trace := range res.Traces {
		t.Log(trace)
	}

	for _, test := range tests {
		test := test // needed for t.Parallel()
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if !funcutil.Exists(res.Traces, func(trace backtrace.Trace) bool {
				ok, err := matchTrace(trace, test.matches)
				_ = err
				// // NOTE commented out for debugging
				// if err != nil {
				// 	t.Errorf("failed match: %v in trace: %v", err, trace)
				// }

				return ok
			}) {
				t.Error("no match")
			}
		})
	}
}

type nodeType int

const (
	arg nodeType = iota
	param
	ret
	call
	globalRead
	globalWrite
	boundvar
	freevar
	closure
)

type argval struct {
	val any
	pos int // position of the argument (starting from 0)
}

type match struct {
	typ  nodeType
	val  any // usually a string, nil, or argval
	line int // 0 is invalid, 1+ is valid
}

func matchTrace(trace backtrace.Trace, matches []match) (bool, error) {
	if len(matches) != len(trace) {
		return false, fmt.Errorf("wrong match length: want %d, got %d", len(matches), len(trace))
	}

	for i, m := range matches {
		if trace[i].Pos.Line != m.line {
			return false, fmt.Errorf("wrong line number: want %d, got %d", m.line, trace[i].Pos.Line)
		}

		ok, err := matchNode(trace[i], m)
		if err != nil || !ok {
			return false, fmt.Errorf("failed to match node: %v", err)
		}
	}

	return true, nil
}

func matchNode(tnode backtrace.TraceNode, m match) (bool, error) {
	switch node := tnode.GraphNode.(type) {
	case *dataflow.CallNodeArg:
		mval := m.val.(argval)
		val := mval.val == node.Value().Name() || (mval.val == nil && !backtrace.IsStatic(node))
		pos := mval.pos == node.Index()
		if m.typ == arg && val && pos {
			return true, nil
		}
	case *dataflow.ParamNode:
		if m.typ == param && m.val == node.SsaNode().String() {
			return true, nil
		}
	case *dataflow.ReturnValNode:
		// TODO support multiple return values
		if m.typ == ret {
			return true, nil
		}
	case *dataflow.CallNode:
		if m.typ == call && m.val == node.FuncName() {
			return true, nil
		} else if m.typ == call && m.val == nil {
			return true, nil
		}
	case *dataflow.AccessGlobalNode:
		if m.typ == globalRead && !node.IsWrite && m.val == node.Instr().String() {
			return true, nil
		} else if m.typ == globalWrite && node.IsWrite && strings.HasPrefix(node.Instr().String(), m.val.(string)) {
			// global write instructions look like:
			// *global = ...
			//
			// we only care about checking the left-hand side of the statement because the right-hand side can vary
			return true, nil
		}
	case *dataflow.BoundVarNode:
		if m.typ == boundvar && m.val == node.Value().String() {
			return true, nil
		}
	case *dataflow.FreeVarNode:
		if m.typ == freevar && m.val == node.SsaNode().Name() {
			return true, nil
		}
	case *dataflow.ClosureNode:
		if m.typ == closure && m.val == node.Instr().String() {
			return true, nil
		}
	default:
		return false, fmt.Errorf("unhandled node type: %T", node)
	}

	return false, fmt.Errorf("no match: %+v, node: %+v", m, tnode)
}
