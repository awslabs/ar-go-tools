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
	"github.com/awslabs/ar-go-tools/cmd/argot/backtrace"
	"github.com/awslabs/ar-go-tools/cmd/argot/cli"
	"github.com/awslabs/ar-go-tools/cmd/argot/compare"
	"github.com/awslabs/ar-go-tools/cmd/argot/defers"
	"github.com/awslabs/ar-go-tools/cmd/argot/dependencies"
	"github.com/awslabs/ar-go-tools/cmd/argot/maypanic"
	"github.com/awslabs/ar-go-tools/cmd/argot/packagescan"
	"github.com/awslabs/ar-go-tools/cmd/argot/reachability"
	"github.com/awslabs/ar-go-tools/cmd/argot/render"
	"github.com/awslabs/ar-go-tools/cmd/argot/statistics"
	"github.com/awslabs/ar-go-tools/cmd/argot/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
)

const usage = `Argot: Automated Reasoning Go Tools
Usage:
  argot [tool] [options] <Go file path(s)>
Tools:
  - taint: performs a taint analysis on a given program
  - backtrace: identifies backwards data-flow traces from function calls
  - cli: interactive terminal-like interface for parts of the analysis
  - compare: prints a comparison of the functions that are reachable according to two different analyses, and the functions that appear in the binary
  - dependencies: prints the dependencies of a given program
  - maypanic: performs a may-panic analysis on a given program
  - packagescan: scans imports in packages
  - reachability: analyzes the program an prints the functions that are reachable within it
  - render: renders a graph representation of the callgraph, or prints the program's SSA form
  - ssa-statistics: prints statistics about the SSA representation of the program
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
	switch cmd := os.Args[1]; cmd {
	case "backtrace":
		flags, err := tools.NewCommonFlags("backtrace", args, backtrace.Usage)
		if err != nil {
			errExit(err)
		}
		if err := backtrace.Run(flags); err != nil {
			errExit(err)
		}
	case "cli":
		flags, err := tools.NewCommonFlags("cli", args, cli.Usage)
		if err != nil {
			errExit(err)
		}
		cli.Run(flags)
	case "compare":
		flags, err := compare.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := compare.Run(flags); err != nil {
			errExit(err)
		}
	case "defer":
		flags, err := tools.NewCommonFlags("defer", args, defers.Usage)
		if err != nil {
			errExit(err)
		}
		if err := defers.Run(flags.FlagSet.Args(), flags.Verbose); err != nil {
			errExit(err)
		}
	case "dependencies":
		flags, err := dependencies.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := dependencies.Run(flags); err != nil {
			errExit(err)
		}
	case "maypanic":
		flags, err := maypanic.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := maypanic.Run(flags); err != nil {
		}
	case "packagescan":
		flags, err := packagescan.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := packagescan.Run(flags); err != nil {
			errExit(err)
		}
	case "reachability":
		flags, err := reachability.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := reachability.Run(flags); err != nil {
			errExit(err)
		}
	case "render":
		flags, err := render.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := render.Run(flags); err != nil {
			errExit(err)
		}
	case "ssa-statistics":
		flags, err := statistics.NewFlags(args)
		if err != nil {
			errExit(err)
		}
		if err := statistics.Run(flags); err != nil {
			errExit(err)
		}
	case "taint":
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
