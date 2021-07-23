// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// gozer: a tool for analyzing Go programs
// This is the entry point of gozer.
package main

import (
	"flag"
	"fmt"
	"go/build"
	"os"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// flags
type excludeFlags []string

var (
	dependencyAnalysisFlag                 = false
	jsonFlag                               = false
	mode                                   = ssa.BuilderMode(0)
	mayPanicAnalysisFlag                   = false
	mayPanicModelCheckingFlag              = false
	reachableFunctionsFlag                 = false
	ssaStatisticsFlag                      = false
	exclude                   excludeFlags = []string{}
)

func (exclude *excludeFlags) String() string {
	return ""
}

func (exclude *excludeFlags) Set(value string) error {
	*exclude = append(*exclude, value)
	return nil
}

func init() {
	flag.BoolVar(&dependencyAnalysisFlag, "dependency-analysis", false, "quantify the degree of usage of all dependencies")
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	flag.Var(&exclude, "exclude", "path to exclude from analysis")
	flag.BoolVar(&mayPanicAnalysisFlag, "may-panic-analysis", false, "do a light-weight \"may panic\" analysis")
	flag.BoolVar(&mayPanicModelCheckingFlag, "may-panic-model-checking", false, "do (heavy-weight) \"may panic\" model checking")
	flag.BoolVar(&reachableFunctionsFlag, "reachable-functions", false, "do (light-weight) discovery of reachable functions")
	flag.BoolVar(&ssaStatisticsFlag, "ssa-statistics", false, "print out SSA statistics")
}

const usage = `Analyze your Go packages.

Usage:
  gozer package...
  gozer source.go

Use the -help flag to display the options.

Examples:
% gozer hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "gozer: %s\n", err)
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

	if mayPanicModelCheckingFlag {
		cfg.Mode = packages.LoadSyntax
	}

	if !jsonFlag {
		fmt.Fprintf(os.Stdout, Faint("Reading sources")+"\n")
	}

	// load, parse and type check the given packages
	initialPackages, err := packages.Load(cfg, flag.Args()...)
	if err != nil {
		return err
	}

	if len(initialPackages) == 0 {
		return fmt.Errorf("no packages")
	}

	if packages.PrintErrors(initialPackages) > 0 {
		return fmt.Errorf("errors found, exiting")
	}

	// Construct SSA for all the packages we have loaded
	program, packages := ssautil.AllPackages(initialPackages, mode)

	for i, p := range packages {
		if p == nil {
			return fmt.Errorf("cannot build SSA for package %s", initialPackages[i])
		}
	}

	// Build SSA for entire program
	program.Build()

	if !jsonFlag {
		fmt.Fprintf(os.Stdout, Faint("Analyzing")+"\n")
	}

	// get absolute paths for 'exclude'
	excludeAbsolute := makeAbsolute(exclude)

	if ssaStatisticsFlag {
		allFunctions := ssautil.AllFunctions(program)
		ssaStatistics(&allFunctions, excludeAbsolute, jsonFlag)
	} else if mayPanicAnalysisFlag {
		mayPanicAnalyzer(program, excludeAbsolute, jsonFlag)
	} else if mayPanicModelCheckingFlag {
		mayPanicModelChecking(program, excludeAbsolute, jsonFlag)
	} else if dependencyAnalysisFlag {
		dependencyAnalysis(program, jsonFlag)
	} else if reachableFunctionsFlag {
		reachableFunctionsAnalysis(program, jsonFlag)
	} else {
		return fmt.Errorf("no analysis option given")
		fmt.Fprint(os.Stderr, usage)
	}

	return nil
}
