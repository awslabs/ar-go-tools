// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// gozer: a tool for analyzing Go programs
// This is the entry point of gozer.
package main

import (
	"flag"
	"fmt"
	"go/build"
	"os"
	"sort"
	"strings"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/format"

	"github.com/awslabs/argot/analysis/packagescan"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// flags
type excludeFlags []string

var (
	jsonFlag = false
	mode     = ssa.BuilderMode(0)
	pkg      = ""
	inexact  = false
)

func init() {
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.StringVar(&pkg, "p", "unsafe", "package or prefix to scan for")
	flag.BoolVar(&inexact, "i", false, "inexact match - match all subpackages")
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

const usage = `Analyze your Go packages.

Usage:
  packagescan -p package [-i] source.go ... 

Use the -help flag to display the options.

Examples:
% packagescan -p unsafe hello.go
% packagescan -i -p github.com/aws/aws-sdk-go hello.go
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

	fmt.Fprintf(os.Stderr, format.Faint("Scanning sources for "+pkg)+"\n")

	// todo -- do we want to make the choice of platforms a command line argument?
	// I made all three the default as a forcing function ("mechanism") to ensure that I
	// would never again overlook Windows or only report on Mac-specific packages.
	platforms := []string{"windows", "linux", "darwin"}
	results := make(map[string]map[string]bool)

	// todo -- technically we could run these in parallel...
	// (though tbf, the LoadProgram does exploit multiple cores already)
	for _, platform := range platforms {
		program, err := analysis.LoadProgram(nil, platform, mode, flag.Args())
		if err != nil {
			return err
		}

		fmt.Fprintln(os.Stderr, format.Faint("Analyzing for "+platform))

		allPkgs := analysis.AllPackages(ssautil.AllFunctions(program))

		pkgs := packagescan.FindImporters(allPkgs, pkg, !inexact)
		results[platform] = pkgs
	}

	DumpResultsByOS(results)

	return nil
}

// header works around the lack of a ternary operator.  If the platform uses a specific
// package, I want to print the platform name and some spaces.  If it doesn't, I want
// an equivalent number of blank spaces.
func header(s string, present bool) string {
	if present {
		return s + "  "
	}
	return strings.Repeat(" ", len(s)+2)
}

// sortedListFromMapKeys takes a map that is keyed by a string and returns
// a sorted slice of those strings.  This might be useful enough to move
// to analysis/utility.go.  We might want to relax it to accept any
// key that is Stringable.  But I'm still figuring out these generics!
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
// I chose to use the platform name rather than 'X' in case the list was long and any headers
// scrolled off.  I could also have used the first letter of the platform as a mnemonic.
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
