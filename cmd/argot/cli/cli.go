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

// Package cli implements the interactive argot CLI.
package cli

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

// Usage for CLI
const Usage = `Interactive CLI for exploring the program and running various analyses.
Usage:
  argot cli [options] <package path(s)>`

var commands = map[string]func(tt *term.Terminal, s *dataflow.State, command Command, withTest bool) bool{
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

// Run runs a simple CLI-based stdin-stdout server to allow us to explore the code.
func Run(flags tools.CommonFlags) {
	logger := log.New(os.Stdout, "", log.Flags())
	_, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting current directory")
		return
	}

	pConfig, done, _ := seekConfig(flags.ConfigPath, flags.FlagSet.Args())
	if done {
		return
	}

	if pConfig == nil {
		fmt.Fprintf(os.Stderr, "failed to load config")
		return
	}
	// Override config parameters with command-line parameters
	if flags.Verbose {
		pConfig.LogLevel = int(config.DebugLevel)
	}
	logger.Printf(formatutil.Faint("Reading sources") + "\n")
	state.Args = flags.FlagSet.Args()
	// Load the program
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	// Initialize an analyzer state
	cfg := config.NewState(pConfig, "", state.Args, loadOptions)
	dfState, err := result.Bind(result.Bind(loadprogram.NewState(cfg), ptr.NewState), dataflow.NewState).Value()
	if err != nil {
		panic(err)
	}

	// Optional step: running the preamble of the taint analysis
	if pConfig.UseEscapeAnalysis || len(pConfig.TaintTrackingProblems) > 0 {
		err := taint.AnalysisPreamble(dfState)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while running the taint analysis preamble: %v", err)
			os.Exit(1)
		}
	}
	// Start the command line tool with the state containing all the information
	run(dfState, flags.WithTest)
}

func seekConfig(configPath string, args []string) (*config.Config, bool, error) {
	var err error
	pConfig := config.NewDefault()
	if configPath != "" {
		config.SetGlobalConfig(configPath)
		pConfig, err = config.LoadGlobal()
		state.ConfigPath = configPath
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load config %q\n", configPath)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return nil, true, nil
		}
	} else if len(args) == 1 && strings.HasSuffix(args[0], ".go") {
		// Special case: look for config in .go 's folder, if found then set it
		dir := path.Dir(args[0])
		if attemptSettingConfig(&pConfig, dir, "config.yaml") == nil {
			return pConfig, false, nil
		}
		err = attemptSettingConfig(&pConfig, dir, "config.json")
	}
	return pConfig, false, err
}

func attemptSettingConfig(pConfig **config.Config, dir string, filename string) error {
	configFile := path.Join(dir, filename)
	config.SetGlobalConfig(configFile)
	tmpConfig, err := config.LoadGlobal()
	if err != nil {
		// Reset and ignore
		config.SetGlobalConfig("")
		return err
	}
	*pConfig = tmpConfig
	state.ConfigPath = configFile
	return nil
}

// run implements the command line tool, calling interpret for each command until the exit command is input
func run(c *dataflow.State, withTest bool) {
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
		if interpret(tt, c, strings.TrimSpace(command), withTest) {
			break
		}
	}
}

// interpret returns true to stop
func interpret(tt *term.Terminal, c *dataflow.State, command string, withTest bool) bool {
	if command == "" {
		return false
	}
	cmd := ParseCommand(command)

	if cmd.Name == "" {
		return false
	}

	if f, ok := commands[cmd.Name]; ok {
		return f(tt, c, cmd, withTest)
	}
	if cmd.Name == cmdHelpName {
		cmdHelp(tt, c, cmd, withTest)
	} else {
		WriteErr(tt, "Command name %q not recognized.", cmd.Name)
		cmdHelp(tt, c, cmd, withTest)
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
