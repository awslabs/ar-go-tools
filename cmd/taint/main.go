// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

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

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/taint"
	"golang.org/x/tools/go/ssa"
)

var (
	configPath = flag.String("config", "", "Config file path for taint analysis")
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

var (
	buildmode = ssa.BuilderMode(0)
)

const usage = ` Perform taint analysis on your packages.
Usage:
    taint [options] <package path(s)>
Examples:
% taint -config config.yaml package...
Run without config to test pointer analysis running time.
`

func main() {
	var err error
	flag.Parse()

	if flag.NArg() == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	logger := log.New(os.Stdout, "", log.Flags())

	taintConfig := &config.Config{} // empty default config
	if *configPath != "" {
		config.SetGlobalConfig(*configPath)
		taintConfig, err = config.LoadGlobal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %s\n", *configPath)
			return
		}
	}

	logger.Printf(analysis.Faint("Reading sources") + "\n")

	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		return
	}

	start := time.Now()
	analysisInfo, err := taint.Analyze(logger, taintConfig, program)
	duration := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analysis failed: %v\n", err)
		return
	}
	logger.Printf("Analysis took %3.4f s\n", duration.Seconds())
	// Prints location in the SSA

	for sink, sources := range analysisInfo.TaintFlows {
		for source := range sources {
			sourcePos := program.Fset.File(source.Pos()).Position(source.Pos())
			sinkPos := program.Fset.File(sink.Pos()).Position(sink.Pos())
			logger.Printf("%s in function %s:\n\tSink: %s\n\t\t[%s]\n\tSource: %s\n\t\t[%s]\n",
				analysis.Red("A source has reached a sink"),
				sink.Parent().Name(),
				sink.String(),
				sinkPos.String(),
				source.String(),
				sourcePos.String(),
			)
		}
	}

}
