// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// render: a tool for rendering various "visualizations" of Go programs.
// -cgout Given a path for a .dot file, generates the callgraph of the program in that file.
// -ssaout Given a path for a folder, generates subfolders with files containing the ssa represention of
//         each package in that file.

package main

import (
	"flag"
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	render "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/rendering"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"os"
	"time"
)

var (
	modeFlag   = flag.String("buildmode", "pointer", "Type of analysis to run. One of: pointer, cha, rta, static, vta")
	cgOutFlag  = flag.String("cgout", "", "Output file for call graph (no output if not specified)")
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
% render -buildmode pointer  -cgout example.dot package...
Print out all the packages in SSA form
% render -ssaout tmpSsa pacakge...
`

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	// The strings constants are used only here
	var callgraphAnalysisMode analysis.CallgraphAnalysisMode
	// modeFlag cannot be null here
	switch *modeFlag {
	case "pointer":
		callgraphAnalysisMode = analysis.PointerAnalysis
	case "cha":
		callgraphAnalysisMode = analysis.ClassHierarchyAnalysis
	case "rta":
		callgraphAnalysisMode = analysis.RapidTypeAnalysis
	case "vta":
		callgraphAnalysisMode = analysis.VariableTypeAnalysis
	case "static":
		callgraphAnalysisMode = analysis.StaticAnalysis
	default:
		_, _ = fmt.Fprintf(os.Stderr, "analysis %s not recognized", *modeFlag)
		os.Exit(2)
	}

	cfg := &packages.Config{
		// packages.LoadSyntax for given files only
		Mode:  analysis.CallgraphPkgLoadMode,
		Tests: false,
	}

	fmt.Fprintf(os.Stderr, analysis.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(cfg, buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load program: %v", err)
		return
	}

	if cgOutFlag != nil && *cgOutFlag != "" {
		// Compute the call graph
		fmt.Fprintf(os.Stderr, analysis.Faint("Computing call graph")+"\n")
		start := time.Now()
		callGraph, err := callgraphAnalysisMode.ComputeCallgraph(program)
		cgComputeDuration := time.Since(start).Seconds()
		if err != nil {
			fmt.Fprintf(os.Stderr, analysis.Red("Could not compute callgraph: %v", err))
			return
		} else {
			fmt.Fprintf(os.Stderr, analysis.Faint(fmt.Sprintf("Computed in %.3f s\n", cgComputeDuration)))
		}

		fmt.Fprintf(os.Stderr, analysis.Faint("Writing call graph in ")+*cgOutFlag+"\n")

		err = render.GraphvizToFile(callGraph, *cgOutFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not print callgraph:\n%v", err)
			return
		}
	}

	if ssaOutFlag != nil && *ssaOutFlag != "" {
		fmt.Fprintf(os.Stderr, analysis.Faint("Generating SSA in ")+*ssaOutFlag+"\n")
		err := render.OutputSsaPackages(program, *ssaOutFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not print ssa form:\n%v\n", err)
			return
		}
	}
}
