// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// gozer: a tool for analyzing Go programs
// This is the entry point of gozer.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/build"
	"os"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/format"
	"github.com/awslabs/argot/analysis/maypanic"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// flags
type excludeFlags []string

var (
	jsonFlag              = false
	mode                  = ssa.BuilderMode(0)
	exclude  excludeFlags = []string{}
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
	flag.Var((*buildutil.TagsFlag)(&build.Default.BuildTags), "tags", buildutil.TagsFlagDoc)
	flag.Var(&exclude, "exclude", "path to exclude from analysis")

}

const usage = `Analyze your Go packages.

Usage:
  ssa_statistics package...
  ssa_statistics source.go

Use the -help flag to display the options.

Examples:
% ssa_statistics hello.go
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

	fmt.Fprintf(os.Stderr, format.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(nil, "", mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, format.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	excludeAbsolute := maypanic.MakeAbsolute(exclude)

	allFunctions := ssautil.AllFunctions(program)

	result := analysis.SSAStatistics(&allFunctions, excludeAbsolute)
	if jsonFlag {
		buf, _ := json.Marshal(result)
		fmt.Println(string(buf))
	} else {
		fmt.Printf("Number of functions: %d\n", result.NumberOfFunctions)
		fmt.Printf("Number of nonempty functions: %d\n", result.NumberOfNonemptyFunctions)
		fmt.Printf("Number of blocks: %d\n", result.NumberOfBlocks)
		fmt.Printf("Number of instructions: %d\n", result.NumberOfInstructions)
	}

	//analysis.DeferStats(&allFunctions)
	analysis.ClosureStats(&allFunctions)

	return nil
}
