// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
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
	commands  = map[string]func(tt *term.Terminal, cache *dataflow.Cache, command Command) bool{
		cmdBuildGraphName: cmdBuildGraph,
		cmdCallersName:    cmdCallers,
		cmdCalleesName:    cmdCallees,
		cmdCdName:         cmdCd,
		cmdExitName:       cmdExit,
		cmdFocusName:      cmdFocus,
		cmdListName:       cmdList,
		cmdLoadName:       cmdLoad,
		cmdLsName:         cmdLs,
		cmdPackageName:    cmdPackage,
		cmdRebuildName:    cmdRebuild,
		cmdReconfigName:   cmdReconfig,
		cmdShowName:       cmdShow,
		cmdSsaValueName:   cmdSsaValue,
		cmdSsaInstrName:   cmdSsaInstr,
		cmdStateName:      cmdState,
		cmdSummaryName:    cmdSummary,
		cmdSummarizeName:  cmdSummarize,
		cmdTaintName:      cmdTaint,
		cmdUnfocusName:    cmdUnfocus,
		cmdWhereName:      cmdWhere,
	}
)

const usage = ` Command-line tool to query information about the program being analyzed.
Usage:
    argot-cli [options] <package path(s)>
Examples:
% argot-cli -config config.yaml package...
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
	_, err = os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting current directory")
		return
	}

	pConfig := &config.Config{} // empty default config
	if *configPath != "" {
		config.SetGlobalConfig(*configPath)
		pConfig, err = config.LoadGlobal()
		state.ConfigPath = *configPath
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %s\n", *configPath)
			return
		}
	} else if len(flag.Args()) == 1 && strings.HasSuffix(flag.Args()[0], ".go") {
		// Special case: look for config in .go 's folder
		dir := path.Dir(flag.Args()[0])
		configfile := path.Join(dir, "config.yaml")
		config.SetGlobalConfig(configfile)
		tmpConfig, err := config.LoadGlobal()
		if err != nil {
			// Reset and ignore
			config.SetGlobalConfig("")
		} else {
			pConfig = tmpConfig
			state.ConfigPath = configfile

		}
	}

	// Override config parameters with command-line parameters
	if *verbose {
		pConfig.Verbose = true
	}

	logger.Printf(format.Faint("Reading sources") + "\n")
	state.Args = flag.Args()
	// Load the program
	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		return
	}

	// Build the cache with all analyses
	cache, err := dataflow.BuildFullCache(log.Default(), pConfig, program)
	if err != nil {
		panic(err)
	}
	// Start the command line tool with the cache containing all the information
	run(cache)
}

// run implements the command line tool, calling interpret for each command until the exit command is input
func run(c *dataflow.Cache) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	state.TermWidth, _, _ = term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	tt := term.NewTerminal(os.Stdin, "> ")
	c.Logger.SetOutput(tt)
	c.Logger.SetFlags(0) // no prefix
	c.Err.SetOutput(tt)
	c.Err.SetFlags(0)
	tt.AutoCompleteCallback = AutoCompleteOfCache(c)
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
	cmd := ParseCommand(command)

	if cmd.Name == "" {
		return false
	}

	if f, ok := commands[cmd.Name]; ok {
		return f(tt, c, cmd)
	} else {
		if cmd.Name == cmdHelpName {
			cmdHelp(tt, c, cmd)
		} else {
			WriteErr(tt, "Command name \"%s\" not recognized.", cmd.Name)
			cmdHelp(tt, c, cmd)
		}
		return false
	}
}
