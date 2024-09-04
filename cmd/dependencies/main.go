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
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/dependencies"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/ssa"
)

// flags

var (
	jsonFlag       = false
	stdlib         = false
	mode           = ssa.BuilderMode(0)
	covFilename    = ""
	graphFilename  = ""
	configFilename = ""
	csvFilename    = ""
	usageThreshold = 10.0
)

func init() {
	flag.StringVar(&configFilename, "config", "", "configuration file")
	flag.StringVar(&covFilename, "cover", "", "output coverage file")
	flag.StringVar(&graphFilename, "graph", "", "output graphviz file")
	flag.StringVar(&csvFilename, "csv", "", "output results in csv")
	flag.BoolVar(&jsonFlag, "json", false, "output results as JSON")
	flag.BoolVar(&stdlib, "stdlib", false, "include standard library packages")
	flag.Float64Var(&usageThreshold, "usage", 10.0, "usage threshold below which warning produced")
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

	program, pkgs, err := analysis.LoadProgram(nil, "", mode, flag.Args())
	if err != nil {
		return err
	}

	var cfg *config.Config
	if configFilename == "" {
		cfg = config.NewDefault()
	} else {
		cfg, err = config.LoadFromFiles(configFilename)
		if err != nil {
			return fmt.Errorf("failed to load config %s: %s", configFilename, err)
		}
	}
	state, err := dataflow.NewAnalyzerState(program, pkgs,
		config.NewLogGroup(cfg), cfg, []func(state *dataflow.AnalyzerState){})
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer state: %s", err)
	}

	state.Logger.Infof(formatutil.Faint("Analyzing"))

	var coverageWriter io.WriteCloser
	var csvWriter io.WriteCloser

	if covFilename != "" {
		coverageWriter, err = os.OpenFile(covFilename, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer coverageWriter.Close()

		coverageWriter.Write([]byte("mode: set\n"))
	}

	if csvFilename != "" {
		csvWriter, err = os.OpenFile(csvFilename, os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer csvWriter.Close()
		csvWriter.Write([]byte("dependency,loc used,loc total,% used\n"))
	}

	dependencyGraph := dependencies.DependencyAnalysis(state, dependencies.DependencyConfigs{
		JsonFlag:       jsonFlag,
		IncludeStdlib:  stdlib,
		CoverageFile:   coverageWriter,
		CsvFile:        csvWriter,
		UsageThreshold: usageThreshold,
		ComputeGraph:   true,
	})

	if covFilename != "" {
		state.Logger.Infof("Coverage written in: %s", covFilename)
	}

	if dependencyGraph != nil {
		state.Logger.Debugf("Checking cycles in dependency graph")
		if dependencyGraph.Cycles() {
			state.Logger.Errorf("FOUND CYCLES IN THE DEPENDENCY GRAPH")
		}
	}

	if graphFilename != "" {
		state.Logger.Infof("Writing Graphviz in: %s", graphFilename)
		dependencyGraph.DumpAsGraphviz(graphFilename, stdlib)
	}

	return nil
}
