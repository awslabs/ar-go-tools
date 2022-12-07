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
	"golang.org/x/tools/go/ssa"
)

// flags
type excludeFlags []string

var (
	jsonFlag    = false
	excludeMain = false
	excludeInit = false
	mode        = ssa.BuilderMode(0)
)

func init() {
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.BoolVar(&excludeMain, "nomain", false, "exclude main() as a starting point")
	flag.BoolVar(&excludeInit, "noinit", false, "exclude init() as a starting point")
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

const usage = `Analyze your Go packages.

Usage:
  reachability package...
  reachability source.go
  reachability source1.go source2.go

prefix with GOOS and/or GOARCH to analyze a different architecture:
  GOOS=windows GOARCH=amd64 reachability agent/agent.go agent/agent_parser.go agent/agent_windows.go

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

	fmt.Fprintf(os.Stderr, analysis.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(nil, "", mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, analysis.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	reachability.ReachableFunctionsAnalysis(program, excludeMain, excludeInit, jsonFlag)

	return nil
}
