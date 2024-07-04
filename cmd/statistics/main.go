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
	"encoding/json"
	"flag"
	"fmt"
	"go/build"
	"log"
	"os"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
)

// flags
type excludeFlags []string

var (
	jsonFlag              = false
	mode                  = ssa.BuilderMode(0)
	exclude  excludeFlags = []string{}
	prefix                = ""
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
	flag.StringVar(&prefix, "prefix", "", "prefix of packages to print statistics for")
}

const usage = `Analyze your Go packages.

Usage:
  ssa_statistics package...
  ssa_statistics source.go
  ssa_statistics -prefix myrepo/mypackage package...

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

	fmt.Fprintf(os.Stderr, formatutil.Faint("Reading sources")+"\n")

	program, pkgs, err := analysis.LoadProgram(nil, "", mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Analyzing")+"\n")

	// get absolute paths for 'exclude'
	excludeAbsolute := analysisutil.MakeAbsolute(exclude)
	defaultConfig := config.NewDefault()
	logGroup := config.NewLogGroup(defaultConfig)
	analyzer, err := dataflow.NewAnalyzerState(program, pkgs, logGroup, defaultConfig, nil)
	if err != nil {
		logGroup.Errorf("Failed to initialize state ...")
		return nil
	}
	reachableFunctions := analyzer.ReachableFunctions()
	result := analysis.SSAStatistics(&reachableFunctions, excludeAbsolute)
	if jsonFlag {
		buf, _ := json.Marshal(result)
		fmt.Println(string(buf))
	} else {
		fmt.Printf("Number of functions: %d\n", result.NumberOfFunctions)
		fmt.Printf("Number of nonempty functions: %d\n", result.NumberOfNonemptyFunctions)
		fmt.Printf("Number of blocks: %d\n", result.NumberOfBlocks)
		fmt.Printf("Number of instructions: %d\n", result.NumberOfInstructions)
	}

	analysis.ClosureLocationsStats(log.Default(), &reachableFunctions, prefix)

	return nil
}
