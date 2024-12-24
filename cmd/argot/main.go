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

package main

import (
	"fmt"
	"os"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/cmd/argot/alias"
	"github.com/awslabs/ar-go-tools/cmd/argot/backtrace"
	"github.com/awslabs/ar-go-tools/cmd/argot/cli"
	"github.com/awslabs/ar-go-tools/cmd/argot/compare"
	"github.com/awslabs/ar-go-tools/cmd/argot/defers"
	"github.com/awslabs/ar-go-tools/cmd/argot/dependencies"
	"github.com/awslabs/ar-go-tools/cmd/argot/goroutine"
	"github.com/awslabs/ar-go-tools/cmd/argot/immutability"
	"github.com/awslabs/ar-go-tools/cmd/argot/maypanic"
	"github.com/awslabs/ar-go-tools/cmd/argot/packagescan"
	"github.com/awslabs/ar-go-tools/cmd/argot/passthru"
	"github.com/awslabs/ar-go-tools/cmd/argot/reachability"
	"github.com/awslabs/ar-go-tools/cmd/argot/render"
	"github.com/awslabs/ar-go-tools/cmd/argot/statistics"
	"github.com/awslabs/ar-go-tools/cmd/argot/syntactic"
	"github.com/awslabs/ar-go-tools/cmd/argot/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
)

const usage = `Argot: Automated Reasoning Go Tools
Usage:
  argot [tool] [options] <Go file path(s)>
Tools:
  - alias: performs a must-not-alias analysis on pointer values
  - backtrace: identifies backwards data-flow traces from function calls
  - syntactic: runs some syntactic analyses using the SSA representation
  - cli: interactive terminal-like interface for parts of the analysis
  - compare: prints a comparison of the functions that are reachable according to two different analyses, and the functions that appear in the binary
  - dependencies: prints the dependencies of a given program
  - immutability: performs an immutability analysis on pointer values
  - maypanic: performs a may-panic analysis on a given program
  - packagescan: scans imports in packages
  - reachability: analyzes the program an prints the functions that are reachable within it
  - render: renders a graph representation of the callgraph, or prints the program's SSA form
  - ssa-statistics: prints statistics about the SSA representation of the program
  - taint: performs a taint analysis on a given program
Examples:
  Run the interactive CLI: argot cli --config=config.yaml main.go
  Run the taint analysis: argot taint --config=config.yaml main.go`

//gocyclo:ignore
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "error: expected subcommand\n%s\n", usage)
		os.Exit(2)
	}

	// hardcode help flag
	if snd := os.Args[1]; snd == "-help" || snd == "--help" {
		fmt.Println(usage)
		return
	}

	// hardcode version flag
	if snd := os.Args[1]; snd == "-version" || snd == "--version" {
		fmt.Println(analysis.Version)
		return
	}

	args := os.Args[2:]
	switch cmd := os.Args[1]; config.ToolName(cmd) {
	case config.AliasTool:
		flags, err := tools.NewCommonFlags(config.AliasTool, args, alias.Usage)
		if err != nil {
			errExit(err)
		}
		if err := alias.Run(flags); err != nil {
			errExit(err)
		}
	case config.BacktraceTool:
		flags, err := tools.NewCommonFlags(config.BacktraceTool, args, backtrace.Usage)
		if err != nil {
			errExit(err)
		}
		if err := backtrace.Run(flags); err != nil {
			errExit(err)
		}
	case config.CliTool:
		flags, err := tools.NewCommonFlags(config.CliTool, args, cli.Usage)
		if err != nil {
			errExit(err)
		}
		cli.Run(flags)
	case config.CompareTool:
		flags, err := compare.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := compare.Run(flags); err != nil {
			errExit(err)
		}
	case config.DeferTool:
		flags, err := tools.NewCommonFlags(config.DeferTool, args, defers.Usage)
		if err != nil {
			errExit(err)
		}
		if err := defers.Run(flags.FlagSet.Args(), flags.Verbose); err != nil {
			errExit(err)
		}
	case config.DependenciesTool:
		flags, err := dependencies.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := dependencies.Run(flags); err != nil {
			errExit(err)
		}
	case config.GoroutineTool:
		flags, err := tools.NewCommonFlags(config.GoroutineTool, args, goroutine.Usage)
		if err != nil {
			errExit(err)
		}
		if err := goroutine.Run(flags); err != nil {
			errExit(err)
		}
	case config.ImmutabilityTool:
		flags, err := tools.NewCommonFlags(config.ImmutabilityTool, args, immutability.Usage)
		if err != nil {
			errExit(err)
		}
		if err := immutability.Run(flags); err != nil {
			errExit(err)
		}
	case config.MayPanicTool:
		flags, err := maypanic.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := maypanic.Run(flags); err != nil {
			errExit(err)
		}
	case config.PackageScanTool:
		flags, err := packagescan.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := packagescan.Run(flags); err != nil {
			errExit(err)
		}
	case config.PassThruTool:
		flags, err := tools.NewCommonFlags(config.PassThruTool, args, passthru.Usage)
		if err != nil {
			errExit(err)
		}
		if err := passthru.Run(flags); err != nil {
			errExit(err)
		}
	case config.ReachabilityTool:
		flags, err := reachability.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := reachability.Run(flags); err != nil {
			errExit(err)
		}
	case config.RenderTool:
		flags, err := render.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := render.Run(flags); err != nil {
			errExit(err)
		}
	case config.SsaStatisticsTool:
		flags, err := statistics.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := statistics.Run(flags); err != nil {
			errExit(err)
		}
	case config.SyntacticTool:
		flags, err := tools.NewCommonFlags(config.SyntacticTool, args, syntactic.Usage)
		if err != nil {
			errExit(err)
		}
		if err := syntactic.Run(flags); err != nil {
			errExit(err)
		}
	case config.TaintTool:
		flags, err := taint.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := taint.Run(flags); err != nil {
			errExit(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unexpected command: %v\n", cmd)
		fmt.Fprintf(os.Stderr, "usage:\n%s\n", usage)
	}
}

func errExit(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	hint := tools.HintForErrorMessage(err.Error())
	if hint != "" {
		fmt.Fprintf(os.Stderr, "Hint: %s\n", hint)
	}
	os.Exit(2)
}
