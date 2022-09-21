// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// gozer: a tool for analyzing Go programs
// This is the entry point of gozer.
package main

import (
	"flag"
	"fmt"
	"go/build"
	"os"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/reachability"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// flags
type excludeFlags []string

var (
	jsonFlag = false
	mode     = ssa.BuilderMode(0)
)

func init() {
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

const usage = `Analyze your Go packages.

Usage:
  reachability package...
  reachability source.go

Use the -help flag to display the options.

Examples:
% reachability hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "reachability: %s\n", err)
		os.Exit(1)
	}
}

func doMain() error {

	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cfg := &packages.Config{
		// packages.LoadSyntax for given files only
		Mode:  packages.LoadAllSyntax,
		Tests: false,
	}

	fmt.Fprintf(os.Stderr, analysis.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(cfg, mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, analysis.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	reachability.ReachableFunctionsAnalysis(program, jsonFlag)

	return nil
}
