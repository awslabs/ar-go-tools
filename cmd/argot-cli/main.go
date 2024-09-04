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
	"log"
	"os"
	"os/signal"
	"path"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

var (
	configPath = flag.String("config", "", "Config file path for  analysis")
	verbose    = flag.Bool("verbose", false, "Verbose printing on standard output")
	withTest   = flag.Bool("with-test", false, "load test when loading program in cli")
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

var (
	buildmode = ssa.InstantiateGenerics
	version   = "unknown"
	commands  = map[string]func(tt *term.Terminal, s *dataflow.AnalyzerState, command Command) bool{
		cmdBuildGraphName:   cmdBuildGraph,
		cmdCallersName:      cmdCallers,
		cmdCalleesName:      cmdCallees,
		cmdCdName:           cmdCd,
		cmdExitName:         cmdExit,
		cmdFocusName:        cmdFocus,
		cmdIntraName:        cmdIntra,
		cmdListName:         cmdList,
		cmdLoadName:         cmdLoad,
		cmdLsName:           cmdLs,
		cmdMarkName:         cmdMark,
		cmdMayAliasName:     cmdMayAlias,
		cmdPackageName:      cmdPackage,
		cmdRebuildName:      cmdRebuild,
		cmdReconfigName:     cmdReconfig,
		cmdScanName:         cmdScan,
		cmdShowSsaName:      cmdShowSsa,
		cmdShowEscapeName:   cmdShowEscape,
		cmdShowDataflowName: cmdShowDataflow,
		cmdSsaInstrName:     cmdSsaInstr,
		cmdSsaValueName:     cmdSsaValue,
		cmdStateName:        cmdState,
		cmdStatsName:        cmdStats,
		cmdSummaryName:      cmdSummary,
		cmdSummarizeName:    cmdSummarize,
		cmdTaintName:        cmdTaint,
		cmdTraceName:        cmdTrace,
		cmdUnfocusName:      cmdUnfocus,
		cmdWhereName:        cmdWhere,
		cmdBacktraceName:    cmdBacktrace,
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

	pConfig, done, _ := seekConfig()
	if done {
		return
	}

	// Override config parameters with command-line parameters
	if *verbose {
		pConfig.LogLevel = int(config.DebugLevel)
	}
	logger.Printf(formatutil.Faint(fmt.Sprintf("argot-cli version %s", version))) // safe %s
	logger.Printf(formatutil.Faint("Reading sources") + "\n")
	state.Args = flag.Args()
	// Load the program
	program, pkgs, err := analysis.LoadProgram(nil, "", buildmode, *withTest, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		return
	}
	// Initialize an analyzer state
	state, err := dataflow.NewInitializedAnalyzerState(program, pkgs, config.NewLogGroup(pConfig), pConfig)
	if err != nil {
		panic(err)
	}

	// Optional step: running the preamble of the taint analysis
	if pConfig.UseEscapeAnalysis || len(pConfig.TaintTrackingProblems) > 0 {
		err := taint.AnalysisPreamble(state)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while running the taint analysis preamble: %v", err)
			os.Exit(1)
		}
	}
	// Start the command line tool with the state containing all the information
	run(state)
}

func seekConfig() (*config.Config, bool, error) {
	var err error
	pConfig := &config.Config{} // empty default config
	if *configPath != "" {
		config.SetGlobalConfig(*configPath)
		pConfig, err = config.LoadGlobal()
		state.ConfigPath = *configPath
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %q\n", *configPath)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return nil, true, nil
		}
	} else if len(flag.Args()) == 1 && strings.HasSuffix(flag.Args()[0], ".go") {
		// Special case: look for config in .go 's folder
		dir := path.Dir(flag.Args()[0])
		pConfig, err = attemptSettingConfig(pConfig, dir, "config.yaml")
		if err == nil {
			return pConfig, false, nil
		}
		pConfig, err = attemptSettingConfig(pConfig, dir, "config.json")
	}
	return pConfig, false, err
}

func attemptSettingConfig(pConfig *config.Config, dir string, filename string) (*config.Config, error) {
	configfile := path.Join(dir, filename)
	config.SetGlobalConfig(configfile)
	tmpConfig, err := config.LoadGlobal()
	if err != nil {
		// Reset and ignore
		config.SetGlobalConfig("")
		return nil, err
	}
	pConfig = tmpConfig
	state.ConfigPath = configfile
	return pConfig, nil
}

// run implements the command line tool, calling interpret for each command until the exit command is input
func run(c *dataflow.AnalyzerState) {
	oldState /* const */, err := term.MakeRaw(int(os.Stdin.Fd()))
	state.TermWidth, _, _ = term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	tt := term.NewTerminal(os.Stdin, "> ")
	c.Logger.SetAllOutput(tt)
	c.Logger.SetAllFlags(0) // no prefix
	tt.AutoCompleteCallback = AutoCompleteOfAnalyzerState(c)
	// if we get a SIGINT, we exit
	// Capture ctrl+c and exit by returning
	captureChan := make(chan os.Signal, 1)
	signal.Notify(captureChan, os.Interrupt)
	go exitOnReceive(captureChan, tt, oldState)
	// the infinite loop terminates when interpret returns true
	for {
		command, _ := tt.ReadLine()
		if interpret(tt, c, strings.TrimSpace(command)) {
			break
		}
	}
}

// interpret returns true to stop
func interpret(tt *term.Terminal, c *dataflow.AnalyzerState, command string) bool {
	if command == "" {
		return false
	}
	cmd := ParseCommand(command)

	if cmd.Name == "" {
		return false
	}

	if f, ok := commands[cmd.Name]; ok {
		return f(tt, c, cmd)
	}
	if cmd.Name == cmdHelpName {
		cmdHelp(tt, c, cmd)
	} else {
		WriteErr(tt, "Command name %q not recognized.", cmd.Name)
		cmdHelp(tt, c, cmd)
	}
	return false
}

func exitOnReceive(c chan os.Signal, tt *term.Terminal, oldState *term.State) {
	for range c {
		writeFmt(tt, formatutil.Red("Caught SIGINT, exiting!"))
		term.Restore(int(os.Stdin.Fd()), oldState)
		os.Exit(0)
	}
}
