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

// Package statistics implements the front-end for the SSA statistics analysis.
package statistics

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

const usage = `Compute SSA statistics for a Go program.

Usage:
  argot ssa-statistics package...
  argot ssa-statistics source.go
  argot ssa-statistics -prefix myrepo/mypackage package...

Use the -help flag to display the options.

Examples:
% argot ssa-statistics hello.go
`

// Flags represents the flags for the ssa-statistics sub-tool.
type Flags struct {
	tools.CommonFlags
	outputJson   bool
	excludePaths []string
	prefix       string
}

// NewFlags returns parsed flags for ssa-statistics.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags("ssa-statistics")
	outputJson := flags.FlagSet.Bool("json", false, "output results as JSON")
	prefix := flags.FlagSet.String("prefix", "", "prefix of packages to print statistics for")
	var exclude tools.ExcludePaths
	flags.FlagSet.Var(&exclude, "exclude", "paths to exclude from analysis")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command ssa-statistics with args %v: %v", args, err)
	}

	return Flags{
		CommonFlags: tools.CommonFlags{
			FlagSet:    flags.FlagSet,
			ConfigPath: *flags.ConfigPath,
			Verbose:    *flags.Verbose,
			WithTest:   *flags.WithTest,
		},
		outputJson:   *outputJson,
		excludePaths: exclude,
		prefix:       *prefix,
	}, nil
}

// Run runs the SSA statistics analysis on args.
func Run(flags Flags) error {
	fmt.Fprintf(os.Stderr, formatutil.Faint("Reading sources")+"\n")

	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Analyzing")+"\n")
	// get absolute paths for 'exclude'
	excludeAbsolute := analysisutil.MakeAbsolute(flags.excludePaths)
	defaultConfig := config.NewDefault()
	c := config.NewState(defaultConfig, "", flags.FlagSet.Args(), loadOptions)
	analyzer, err := loadprogram.NewState(c).Value()
	if err != nil {
		c.Logger.Errorf("Failed to initialize state ...")
		return nil
	}
	reachableFunctions, err := analyzer.ReachableFunctions()
	if err != nil {
		return fmt.Errorf("error computing reachable functions: %s", err)
	}
	result := analysis.SSAStatistics(&reachableFunctions, excludeAbsolute)
	if flags.outputJson {
		buf, _ := json.Marshal(result)
		c.Logger.Infof(string(buf))
	} else {
		c.Logger.Infof("Number of functions: %d\n", result.NumberOfFunctions)
		c.Logger.Infof("Number of nonempty functions: %d\n", result.NumberOfNonemptyFunctions)
		c.Logger.Infof("Number of blocks: %d\n", result.NumberOfBlocks)
		c.Logger.Infof("Number of instructions: %d\n", result.NumberOfInstructions)
	}

	analysis.ClosureLocationsStats(log.Default(), &reachableFunctions, flags.prefix)

	return nil
}
