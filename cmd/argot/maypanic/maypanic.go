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

// Package maypanic implements the front-end to the maypanic anaylsis.
package maypanic

import (
	"flag"
	"fmt"
	"go/build"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/maypanic"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// Flags represents the parsed maypanic sub-command flags.
type Flags struct {
	outputJson   bool
	excludePaths []string
	flagSet      *flag.FlagSet
}

// NewFlags returns the parsed maypanic flags from args.
func NewFlags(args []string) (Flags, error) {
	cmd := flag.NewFlagSet("maypanic", flag.ExitOnError)
	outputJson := cmd.Bool("json", false, "output results as JSON")
	var exclude tools.ExcludePaths
	cmd.Var(&exclude, "exclude", "path to exclude from analysis")
	cmd.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	tools.SetUsage(cmd, usage)
	if err := cmd.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command maypanic with args %v: %v", args, err)
	}

	return Flags{
		outputJson:   *outputJson,
		excludePaths: exclude,
		flagSet:      cmd,
	}, nil
}

const usage = `Analyze your Go packages for potential panics.

Usage:
  argot maypanic package...
  argot maypanic source.go

Use the -help flag to display the options.

Examples:
% argot maypanic hello.go
`

// Run runs the analysis with flags.
func Run(flags Flags) error {
	// TODO: LoadAllSyntax is deprecated
	//goland:noinspection GoDeprecation
	cfg := &packages.Config{
		// packages.LoadSyntax for given files only
		Mode:  packages.LoadAllSyntax,
		Tests: false,
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Reading sources")+"\n")

	// never load tests for the may-panic analysis (may change later if there's an ask)
	loadOptions := config.LoadOptions{
		PackageConfig: cfg,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     false,
		ApplyRewrites: true,
	}
	base := config.NewState(config.NewDefault(), "", flags.flagSet.Args(), loadOptions)
	state, err := loadprogram.NewState(base).Value()
	if err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	excludeAbsolute := analysisutil.MakeAbsolute(flags.excludePaths)

	maypanic.MayPanicAnalyzer(state.Program, excludeAbsolute, flags.outputJson)

	return nil
}
