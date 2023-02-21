// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/concurrency"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/format"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
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

const usage = ` Lightweight concurrency analysis.
Usage:
    concur [options] <package path(s)>
Examples:
% concur -config config.yaml package...
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

	analysisConfig := &config.Config{} // empty default config
	if *configPath != "" {
		config.SetGlobalConfig(*configPath)
		analysisConfig, err = config.LoadGlobal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %s\n", *configPath)
			return
		}
	}

	// Override config parameters with command-line parameters
	if *verbose {
		analysisConfig.Verbose = true
	}

	logger.Printf(format.Faint("Reading sources") + "\n")

	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		return
	}

	start := time.Now()
	_, err = concurrency.Analyze(logger, analysisConfig, program)
	duration := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analysis failed: %v\n", err)
		return
	}
	logger.Printf("Analysis took %3.4f s\n", duration.Seconds())
}
