// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"flag"
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/defers"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/format"
	"go/build"
	"os"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
)

// flags
var (
	mode    = ssa.BuilderMode(0)
	verbose = false
)

func init() {
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

const usage = `Analyze defer statements.

Usage:
  defer package...
  defer source.go
  defer source1.go source2.go

prefix with GOOS and/or GOARCH to analyze a different architecture:
  GOOS=windows GOARCH=amd64 defer agent/agent.go agent/agent_parser.go agent/agent_windows.go

Use the -help flag to display the options.

Use -verbose for debugging output.

Examples:
$ defer hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "defer: %s\n", err)
		os.Exit(1)
	}
}

func doMain() error {

	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, format.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(nil, "", mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, format.Faint("Analyzing")+"\n")

	defers.AnalyzeProgram(program, verbose)

	return nil
}
