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
	"github.com/awslabs/ar-go-tools/analysis/config/specs"
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
	config      string
	target      string
	tag         string
	outputJson  bool
	pkg         string
	inexact     bool
	all         bool
	platforms   string
	rawFilename string
	withTest    bool
	flagSet     *flag.FlagSet
}

// NewFlags returns the parsed flags from args.
func NewFlags(args []string) (Flags, error) {
	cmd := flag.NewFlagSet("packagescan", flag.ExitOnError)
	config := cmd.String("c", "", "path to config if using targets")
	target := cmd.String("t", "", "target name (needs config)")
	tag := cmd.String("tag", "", "tag of the problem to scan (needs config)")
	outputJson := cmd.Bool("json", false, "output results as JSON")
	pkg := cmd.String("p", "unsafe", "package or prefix to scan for")
	inexact := cmd.Bool("i", false, "inexact match - match all subpackages")
	all := cmd.Bool("a", false, "dump all the packages that are imported (ignore -i and -p)")
	platforms := cmd.String("platforms", "windows,linux,darwin", "target platform(s)")
	rawFilename := cmd.String("raw", "", "filename for dump of raw symbol usage")
	withTest := cmd.Bool("with-test", false, "load test when scanning")
	cmd.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	tools.SetUsage(cmd, usage)
	if err := cmd.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command packagescan with args %v: %v", args, err)
	}
	if *target != "" && *config == "" {
		return Flags{}, fmt.Errorf("you should specify a config when specifying a target")
	}
	if *tag != "" && *config == "" {
		return Flags{}, fmt.Errorf("you should specify a config when specifying a tag")
	}
	if *target != "" && len(cmd.Args()) > 0 {
		return Flags{}, fmt.Errorf("you should specify either a target or package patterns, not both")
	}

	return Flags{
		config:      *config,
		target:      *target,
		tag:         *tag,
		outputJson:  *outputJson,
		pkg:         *pkg,
		inexact:     *inexact,
		all:         *all,
		platforms:   *platforms,
		rawFilename: *rawFilename,
		withTest:    *withTest,
		flagSet:     cmd,
	}, nil
}

const usage = `Analyze your Go packages.

Usage:
  argot packagescan [-c config] [-t target] [-p package] [-i] [source.go] ...

Use the -help flag to display the options.

Examples:
  % argot packagescan -p unsafe hello.go
  % argot packagescan -p unsafe hello.go
  % argot packagescan -i -p github.com/aws/aws-sdk-go hello.go
  % argot packagescan -a hello.go
  % argot packagescan -c config.yaml -t sample-target
`

// Run runs the packagescan analysis with flags.
func Run(flags Flags) error {
	fmt.Fprintf(os.Stderr, formatutil.Faint("Scanning sources for package "+flags.pkg)+"\n")

	if flags.config != "" && flags.target != "" {
		return runTargetMode(flags)
	}
	return runRawMode(flags)
}

func runTargetMode(flags Flags) error {
	cfg, err := config.LoadFromFiles(flags.config, nil)
	if err != nil {
		return err
	}

	c, err := config.NewAutoState(cfg, flags.target, flags.withTest)
	if err != nil {
		return fmt.Errorf("error preparing config: %w", err)
	}
	state, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
	if err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}
	// If there is some package usage to scan for, then scan for the usages
	if flags.pkg != "" {
		// Scan for package usages
		pkgScanResults := make(map[string]map[string]bool)
		analyzePackages(state, flags, state.Options.Platform, pkgScanResults)
		dumpResultsByOs(pkgScanResults)
	}
	// If there is a tag specified, then scan for entry points for that problem
	for _, spec := range c.Config.GetSpecs() {
		if spec.SpecTag() == flags.tag {
			switch specKind := spec.(type) {
			case *specs.Taint:
				scanTaintSpec(state, flags, specKind)
			case *specs.Slicing:
				scanSlicingSpec(state, flags, specKind)
			case *specs.CondCheckSpec:
				scanCondCheckSpec(state, flags, specKind)
			case *specs.StructInitSpec:
				scanStructInitSpec(state, flags, specKind)
			}
		}
	}
	return nil
}

func scanTaintSpec(state *ptr.State, flags Flags, ts *specs.Taint) {
	state.Logger.Infof("scanning for taint specs not implemented, skipping")
}

func scanSlicingSpec(state *ptr.State, flags Flags, ss *specs.Slicing) {
	state.Logger.Infof("scanning for slicing specs not implemented, skipping")
}

func scanCondCheckSpec(state *ptr.State, flags Flags, ccs *specs.CondCheckSpec) {
	state.Logger.Infof("scanning for precondition checking not implemented, skipping)")
}

func scanStructInitSpec(state *ptr.State, flags Flags, sis *specs.StructInitSpec) {
	state.Logger.Infof("scanning for struct init specs not implemented, skipping")
}

func runRawMode(flags Flags) error {
	platforms := strings.Split(flags.platforms, ",")
	pkgScanResults := make(map[string]map[string]bool)
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
		analyzePackages(state, flags, platform, pkgScanResults)
	}
	dumpResultsByOs(pkgScanResults)
	return nil
}

func analyzePackages(
	state *ptr.State,
	flags Flags,
	platform string,
	pkgScanResult map[string]map[string]bool) {
	var rawFile io.WriteCloser
	if flags.rawFilename != "" {
		rawFile, err := os.OpenFile(flags.rawFilename, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			state.Logger.Errorf("failed to load raw file: %q", err)
			os.Exit(1)
		}
		defer rawFile.Close()
	}
	pkg := flags.pkg
	if flags.all {
		pkg = "" // an empty package list will match everything.
	}
	fmt.Fprintln(os.Stderr, formatutil.Faint("Analyzing for "+platform))
	allPkgs := loadprogram.AllPackages(state.ReachableFunctions())
	pkgScanResult[platform] = FindImporters(allPkgs, pkg, !flags.inexact, rawFile)
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

// dumpResultsByOs creates a tabular representation of the output, printing fixed size columns for
// the package's presence in each of the target OS's, followed by the name of the package name.
// We use the platform name rather than 'X' in case the list was long and any headers
// scrolled off.  We could also have used the first letter of the platform as a mnemonic.
// results is a map from platform name to a set of packages that import the target on that platform
func dumpResultsByOs(results map[string]map[string]bool) {
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
