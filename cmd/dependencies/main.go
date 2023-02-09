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
	"io"
	"log"
	"os"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dependencies"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
)

// flags

var (
	jsonFlag      = false
	stdlib        = false
	mode          = ssa.BuilderMode(0)
	covFilename   = ""
	graphFilename = ""
)

func init() {
	flag.StringVar(&covFilename, "cover", "", "output coverage file")
	flag.StringVar(&graphFilename, "graph", "", "output graphviz file")
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.BoolVar(&stdlib, "stdlib", false, "include standard library packages")
	flag.Var(&mode, "build", ssa.BuilderModeDoc)
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
}

const usage = `Analyze your Go packages.

Usage:
  dependencies package...
  dependencies source.go

Use the -help flag to display the options.

Examples:
% dependencies hello.go
`

func main() {
	if err := doMain(); err != nil {
		fmt.Fprintf(os.Stderr, "dependencies: %s\n", err)
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

	var outfile io.WriteCloser

	if covFilename != "" {
		outfile, err = os.OpenFile(covFilename, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer outfile.Close()

		outfile.Write([]byte("mode: set\n"))
	}

	dependencyGraph := dependencies.DependencyAnalysis(program, jsonFlag, stdlib, outfile, graphFilename != "")

	if dependencyGraph != nil {
		//fmt.Println("Checking cycles in dependency graph")
		if dependencyGraph.Cycles() {
			fmt.Println("FOUND CYCLES IN THE DEPENDENCY GRAPH")
		}
	}

	if graphFilename != "" {
		dependencyGraph.DumpAsGraphviz(graphFilename, stdlib)
	}

	return nil
}