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

// render: a tool for rendering various "visualizations" of Go programs.
// -cgout Given a path for a .dot file, generates the callgraph of the program in that file.
// -ssaout Given a path for a folder, generates subfolders with files containing the ssa represention of
//         each package in that file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/colors"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

var (
	modeFlag   = flag.String("analysis", "pointer", "Type of analysis to run. One of: pointer, cha, rta, static, vta")
	cgOut      = flag.String("cgout", "", "Output file for call graph (no output if not specified)")
	htmlOut    = flag.String("htmlout", "", "Output file for call graph (no output if not specified)")
	dfOut      = flag.String("dfout", "", "Output file for cross-function dataflow graph (no output if not specified)")
	configPath = flag.String("config", "", "Config file")
	ssaOutFlag = flag.String("ssaout", "", "Output folder for ssa (no output if not specified)")
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

var (
	buildmode = ssa.BuilderMode(0)
)

const usage = ` Render callgraphs or ssa representation of your packages.
Usage:
    render [options] <package path(s)>
Examples:
Render a callgraph computed using pointer analysis
% render -analysis pointer  -cgout example.dot package...
Print out all the packages in SSA form
% render -ssaout tmpSsa package...
`

func main() {
	var err error

	flag.Parse()

	if flag.NArg() == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	logger := log.Default()

	// The strings constants are used only here
	var callgraphAnalysisMode dataflow.CallgraphAnalysisMode
	// modeFlag cannot be null here
	switch *modeFlag {
	case "pointer":
		callgraphAnalysisMode = dataflow.PointerAnalysis
	case "cha":
		callgraphAnalysisMode = dataflow.ClassHierarchyAnalysis
	case "rta":
		callgraphAnalysisMode = dataflow.RapidTypeAnalysis
	case "vta":
		callgraphAnalysisMode = dataflow.VariableTypeAnalysis
	case "static":
		callgraphAnalysisMode = dataflow.StaticAnalysis
	default:
		_, _ = fmt.Fprintf(os.Stderr, "analysis %s not recognized", *modeFlag)
		os.Exit(2)
	}

	renderConfig := config.NewDefault() // empty default config
	if *configPath != "" {
		config.SetGlobalConfig(*configPath)
		renderConfig, err = config.LoadGlobal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %s\n", *configPath)
			return
		}
	}

	fmt.Fprintf(os.Stderr, colors.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load program: %v", err)
		return
	}

	var cg *callgraph.Graph

	// Compute the call graph
	if *cgOut != "" || *htmlOut != "" {
		fmt.Fprintf(os.Stderr, colors.Faint("Computing call graph")+"\n")
		start := time.Now()
		cg, err = callgraphAnalysisMode.ComputeCallgraph(program)
		cgComputeDuration := time.Since(start).Seconds()
		if err != nil {
			fmt.Fprintf(os.Stderr, colors.Red("Could not compute callgraph: %v", err))
			return
		} else {
			fmt.Fprintf(os.Stderr, colors.Faint(fmt.Sprintf("Computed in %.3f s\n", cgComputeDuration)))
		}
	}

	if *cgOut != "" {
		fmt.Fprintf(os.Stderr, colors.Faint("Writing call graph in "+*cgOut+"\n"))

		err = GraphvizToFile(renderConfig, cg, *cgOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not print callgraph:\n%v", err)
			return
		}
	}

	if *htmlOut != "" {
		fmt.Fprintf(os.Stderr, colors.Faint("Writing call graph in "+*htmlOut+"\n"))
		err = WriteHtmlCallgraph(program, cg, *htmlOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not print callgraph:\n%v\n", err)
		}
	}

	if *dfOut != "" {
		fmt.Fprintf(os.Stderr, colors.Faint("Writing cross-function dataflow graph in "+*dfOut+"\n"))

		f, err := os.Create(*dfOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create file: %v", err)
			return
		}
		defer f.Close()
		if err := WriteCrossFunctionGraph(renderConfig, logger, program, f); err != nil {
			fmt.Fprintf(os.Stderr, "Could not generate cross-function flow graph:\n%v", err)
			return
		}
	}

	if ssaOutFlag != nil && *ssaOutFlag != "" {
		fmt.Fprintf(os.Stderr, colors.Faint("Generating SSA in ")+*ssaOutFlag+"\n")
		err := OutputSsaPackages(program, *ssaOutFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not print ssa form:\n%v\n", err)
			return
		}
	}
}
