// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/format"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

var (
	configPath = flag.String("config", "", "Config file path for  analysis")
	verbose    = flag.Bool("verbose", false, "Verbose printing on standard output")
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

var (
	buildmode = ssa.BuilderMode(0)
	commands  = map[string]func(tt *term.Terminal, cache *dataflow.Cache, command string) bool{
		cmdBuildGraphName: cmdBuildGraph,
		cmdCallersName:    cmdCallers,
		cmdExitName:       cmdExit,
		cmdListName:       cmdList,
		cmdLsName:         cmdLs,
		cmdRebuildName:    cmdRebuild,
		cmdReconfigName:   cmdReconfig,
		cmdShowName:       cmdShow,
		cmdSummaryName:    cmdSummary,
		cmdSummarizeName:  cmdSummarize,
		cmdTaintName:      cmdTaint,
	}
)

const usage = ` Query information about the program being analyzed.
Usage:
    server [options] <package path(s)>
Examples:
% taint -config config.yaml package...
Options:
`

// This is a simple stdin-stdout server to allow us to explore the code

func main() {
	var err error
	flag.Parse()

	if flag.NArg() == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	logger := log.New(os.Stdout, "", log.Flags())
	curDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting current directory")
		return
	}
	state.Wd = curDir
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
	// Load the program
	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		return
	}

	// Build the cache with all analyses
	cache, err := dataflow.BuildFullCache(log.Default(), taintConfig, program)
	if err != nil {
		panic(err)
	}
	run(cache)
}

func run(c *dataflow.Cache) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	tt := term.NewTerminal(os.Stdin, "> ")
	c.Logger.SetOutput(tt)
	c.Logger.SetFlags(0) // no prefix
	// the infinite loop terminates when interpret returns true
	for {
		command, _ := tt.ReadLine()
		if interpret(tt, c, strings.TrimSpace(command)) {
			break
		}
	}
}

// interpret returns true to stop
func interpret(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if command == "" {
		return false
	}
	parts := strings.Split(command, " ")
	if len(parts) > 0 {
		prefix := parts[0]
		if f, ok := commands[prefix]; ok {
			return f(tt, c, command)
		} else {
			if prefix == cmdHelpName {
				cmdHelp(tt, c, command)
			} else {
				WriteErr(tt, "Command prefix \"%s\" not recognized.", prefix)
				cmdHelp(tt, c, command)
			}
			return false
		}
	} else {
		WriteErr(tt, "Command \"%s\" not recognized.", command)
		return false
	}
}
