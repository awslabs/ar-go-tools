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
	"log"
	"os"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/dependencies"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
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

	fmt.Fprintf(os.Stderr, formatutil.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(nil, "", mode, flag.Args())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, formatutil.Faint("Analyzing")+"\n")

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
