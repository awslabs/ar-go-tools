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
	"flag"
	"fmt"
	"go/build"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/internal/colors"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// flags
type excludeFlags []string

var (
	jsonFlag    = false
	all         = false
	mode        = ssa.BuilderMode(0)
	pkg         = ""
	inexact     = false
	targets     = ""
	rawFilename = ""
)

func init() {
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.StringVar(&pkg, "p", "unsafe", "package or prefix to scan for")
	flag.BoolVar(&inexact, "i", false, "inexact match - match all subpackages")
	flag.BoolVar(&all, "a", false, "dump all the packages that are imported (ignore -i and -p)")
	flag.StringVar(&targets, "target", "windows,linux,darwin", "target platform(s)")
	flag.StringVar(&rawFilename, "raw", "", "filename for dump of raw symbol usage")
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

const usage = `Analyze your Go packages.

Usage:
  packagescan -p package [-i] source.go ...

Use the -help flag to display the options.

Examples:
% packagescan -p unsafe hello.go
% packagescan -p unsafe hello.go
% packagescan -i -p github.com/aws/aws-sdk-go hello.go
% packagescan -a hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "ssa_statistics: %s\n", err)
		os.Exit(1)
	}
}

func doMain() error {

	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, colors.Faint("Scanning sources for "+pkg)+"\n")

	var rawFile io.WriteCloser

	if rawFilename != "" {
		rawFile, err := os.OpenFile(rawFilename, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer rawFile.Close()

	}

	if all {
		pkg = "" // an empty package list will match everything.
	}

	platforms := strings.Split(targets, ",")
	results := make(map[string]map[string]bool)

	// todo -- technically we could run these in parallel...
	// (though tbf, the LoadProgram does exploit multiple cores already)
	for _, platform := range platforms {
		program, err := analysis.LoadProgram(nil, platform, mode, flag.Args())
		if err != nil {
			return err
		}

		fmt.Fprintln(os.Stderr, colors.Faint("Analyzing for "+platform))

		allPkgs := analysis.AllPackages(ssautil.AllFunctions(program))

		pkgs := FindImporters(allPkgs, pkg, !inexact, rawFile)
		results[platform] = pkgs
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

	for k, _ := range m {
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
