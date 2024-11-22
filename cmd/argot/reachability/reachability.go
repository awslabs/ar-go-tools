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

package reachability

import (
	"fmt"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/reachability"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// Flags represents the parsed flags for the reachability sub-command.
type Flags struct {
	tools.CommonFlags
	outputJson  bool
	excludeMain bool
	excludeInit bool
}

// NewFlags creates parsed reachability sub-command flags for args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags("reachability")
	outputJson := flags.FlagSet.Bool("json", false, "output results as JSON")
	noMain := flags.FlagSet.Bool("nomain", false, "exclude main() as a starting point")
	noInit := flags.FlagSet.Bool("noinit", false, "exclude init() as a starting point")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command reachability with args %v: %v", args, err)
	}

	return Flags{
		CommonFlags: tools.CommonFlags{
			FlagSet:    flags.FlagSet,
			ConfigPath: *flags.ConfigPath,
			Verbose:    *flags.Verbose,
			WithTest:   *flags.WithTest,
		},
		outputJson:  *outputJson,
		excludeMain: *noMain,
		excludeInit: *noInit,
	}, nil
}

const usage = `Find all the reachable functions in your Go program.

Usage:
  argot reachability package...
  argot reachability source.go
  argot reachability source1.go source2.go

prefix with GOOS and/or GOARCH to analyze a different architecture:
  GOOS=windows GOARCH=amd64 argot reachability main_windows.go

Use the -help flag to display the options.

Examples:
% argot reachability hello.go
`

// Run runs the reachability analysis with flags.
func Run(flags Flags) error {
	var err error
	var cfg *config.Config
	if flags.ConfigPath == "" {
		cfg = config.NewDefault()
	} else {
		cfg, err = config.LoadFromFiles(flags.ConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load config %s: %s", flags.ConfigPath, err)
		}
	}
	fmt.Fprintf(os.Stderr, formatutil.Faint("Reading sources")+"\n")
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	c := config.NewState(cfg, "", flags.FlagSet.Args(), loadOptions)
	state, err := loadprogram.NewState(c).Value()
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer state: %s", err)
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	reachability.ReachableFunctionsAnalysis(state, flags.excludeMain, flags.excludeInit, flags.outputJson)

	return nil
}
