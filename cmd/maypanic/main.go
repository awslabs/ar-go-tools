// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// gozer: a tool for analyzing Go programs
// This is the entry point of gozer.
package main

import (
	"flag"
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/format"
	"go/build"
	"os"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/maypanic"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// flags
type excludeFlags []string

var (
	jsonFlag                       = false
	mode                           = ssa.BuilderMode(0)
	modelCheckingFlag              = false
	exclude           excludeFlags = []string{}
)

func (exclude *excludeFlags) String() string {
	return ""
}

func (exclude *excludeFlags) Set(value string) error {
	*exclude = append(*exclude, value)
	return nil
}

func init() {
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	flag.Var(&exclude, "exclude", "path to exclude from analysis")
	flag.BoolVar(&modelCheckingFlag, "may-panic-model-checking", false, "do (heavy-weight) \"may panic\" model checking")
}

const usage = `Analyze your Go packages.

Usage:
  maypanic package...
  maypanic source.go

Use the -help flag to display the options.

Examples:
% maypanic hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "maypanic: %s\n", err)
		os.Exit(1)
	}
}

type nameAndFunction struct {
	name string
	f    *ssa.Function
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

	if modelCheckingFlag {
		cfg.Mode = packages.LoadSyntax // this is equivalent to LoadAllSyntax, less NeedDeps
	}

	fmt.Fprintf(os.Stderr, format.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(cfg, "", mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, format.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	excludeAbsolute := maypanic.MakeAbsolute(exclude)

	if modelCheckingFlag {
		maypanic.MayPanicModelChecking(program, excludeAbsolute, jsonFlag)
	} else {

		maypanic.MayPanicAnalyzer(program, excludeAbsolute, jsonFlag)
	}

	return nil
}
