// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/format"

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/taint"
	"golang.org/x/tools/go/ssa"
)

var (
	configPath = flag.String("config", "", "Config file path for taint analysis")
	verbose    = flag.Bool("verbose", false, "Verbose printing on standard output")
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

	// Override config parameters with command-line parameters
	if *verbose {
		taintConfig.Verbose = true
	}

	logger.Printf(format.Faint("Reading sources") + "\n")

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
	logger.Printf("")
	logger.Printf("-%s", strings.Repeat("*", 80))
	logger.Printf("Analysis took %3.4f s", duration.Seconds())
	logger.Printf("")
	if len(analysisInfo.TaintFlows) == 0 {
		logger.Printf("RESULT:\n\t\t%s", format.Green("No taint flows detected ✓"))
	} else {
		logger.Printf("RESULT:\n\t\t%s", format.Red("Taint flows detected!"))
	}

	// Prints location in the SSA
	for sink, sources := range analysisInfo.TaintFlows {
		for source := range sources {
			sourcePos := program.Fset.File(source.Pos()).Position(source.Pos())
			sinkPos := program.Fset.File(sink.Pos()).Position(sink.Pos())
			logger.Printf("%s in function %s:\n\tSink: [SSA] %s\n\t\t%s\n\tSource: [SSA] %s\n\t\t%s\n",
				format.Red("A source has reached a sink"),
				sink.Parent().Name(),
				sink.String(),
				sinkPos.String(),
				source.String(),
				sourcePos.String(),
			)
		}
	}
}
