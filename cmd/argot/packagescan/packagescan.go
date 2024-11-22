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

// Package packagescan implements the front-end to the packagescan analysis.
package packagescan

import (
	"flag"
	"fmt"
	"go/build"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
)

// Flags represents the parsed packagescan sub-command flags.
type Flags struct {
	outputJson  bool
	pkg         string
	inexact     bool
	all         bool
	targets     string
	rawFilename string
	withTest    bool
	flagSet     *flag.FlagSet
}

// NewFlags returns the parsed flags from args.
func NewFlags(args []string) (Flags, error) {
	cmd := flag.NewFlagSet("packagescan", flag.ExitOnError)
	outputJson := cmd.Bool("json", false, "output results as JSON")
	pkg := cmd.String("p", "unsafe", "package or prefix to scan for")
	inexact := cmd.Bool("i", false, "inexact match - match all subpackages")
	all := cmd.Bool("a", false, "dump all the packages that are imported (ignore -i and -p)")
	targets := cmd.String("target", "windows,linux,darwin", "target platform(s)")
	rawFilename := cmd.String("raw", "", "filename for dump of raw symbol usage")
	withTest := cmd.Bool("with-test", false, "load test when scanning")
	cmd.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	tools.SetUsage(cmd, usage)
	if err := cmd.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command packagescan with args %v: %v", args, err)
	}

	return Flags{
		outputJson:  *outputJson,
		pkg:         *pkg,
		inexact:     *inexact,
		all:         *all,
		targets:     *targets,
		rawFilename: *rawFilename,
		withTest:    *withTest,
		flagSet:     cmd,
	}, nil
}

const usage = `Analyze your Go packages.

Usage:
  argot packagescan -p package [-i] source.go ...

Use the -help flag to display the options.

Examples:
  % argot packagescan -p unsafe hello.go
  % argot packagescan -p unsafe hello.go
  % argot packagescan -i -p github.com/aws/aws-sdk-go hello.go
  % argot packagescan -a hello.go
`

// Run runs the packagescan analysis with flags.
func Run(flags Flags) error {
	fmt.Fprintf(os.Stderr, formatutil.Faint("Scanning sources for package "+flags.pkg)+"\n")

	var rawFile io.WriteCloser

	if flags.rawFilename != "" {
		rawFile, err := os.OpenFile(flags.rawFilename, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer rawFile.Close()

	}

	pkg := flags.pkg
	if flags.all {
		pkg = "" // an empty package list will match everything.
	}

	platforms := strings.Split(flags.targets, ",")
	results := make(map[string]map[string]bool)
	cfg := config.NewDefault()
	for _, platform := range platforms {
		loadOptions := config.LoadOptions{
			Platform:      platform,
			PackageConfig: nil,
			BuildMode:     ssa.InstantiateGenerics,
			LoadTests:     flags.withTest,
			ApplyRewrites: true,
		}
		c := config.NewState(cfg, "", flags.flagSet.Args(), loadOptions)
		state, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
		if err != nil {
			return fmt.Errorf("failed to load program: %v", err)
		}
		fmt.Fprintln(os.Stderr, formatutil.Faint("Analyzing for "+platform))
		allPkgs := loadprogram.AllPackages(state.ReachableFunctions())
		results[platform] = FindImporters(allPkgs, pkg, !flags.inexact, rawFile)
	}

	DumpResultsByOS(results)

	return nil
}

// header works around the lack of a ternary operator.  If the platform uses a specific
// package, print the platform name and some spaces.  If it doesn't, instead print
// an equivalent number of spaces.
func header(s string, present bool) string {
	if present {
		return s + "  "
	}
	return strings.Repeat(" ", len(s)+2)
}

// sortedListFromMapKeys takes a map that is keyed by a string and returns
// a sorted slice of those strings.  This might be useful enough to move
// to analysis/utility.go.  We might want to relax it to accept any
// key that is Stringable.
func sortedListFromMapKeys[V any](m map[string]V) []string {
	ret := make([]string, 0, len(m))

	for k := range m {
		ret = append(ret, k)
	}

	sort.Strings(ret)
	return ret
}

// DumpResultsByOS creates a tabular representation of the output, printing fixed size columns for
// the package's presence in each of the target OS's, followed by the name of the package name.
// We use the platform name rather than 'X' in case the list was long and any headers
// scrolled off.  We could also have used the first letter of the platform as a mnemonic.
// results is a map from platform name to a set of packages that import the target on that platform
func DumpResultsByOS(results map[string]map[string]bool) {
	names := sortedListFromMapKeys(results) // list platforms deterministically

	// all is the Union of the package lists from all three platforms.
	all := make(map[string]bool)
	for _, packages := range results {
		for p := range packages {
			all[p] = true
		}
	}
	list := sortedListFromMapKeys(all) // create a deterministic ordering of the package list

	// now loop through the package list, constructing and printing each row.
	for _, pkg := range list {
		row := ""
		for _, platform := range names {
			row += header(platform, results[platform][pkg])
		}
		row += pkg
		fmt.Println(row)
	}
}
