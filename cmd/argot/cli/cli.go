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
	"os"
	"os/signal"
	"strings"

	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/term"
)

// Usage for CLI
const Usage = `Interactive CLI for exploring the program and running various analyses.
Usage:
  argot cli [options] <package path(s)>`

var commands = map[string]func(tt *term.Terminal, s *session, command Command, withTest bool) bool{
	cmdAstName:              cmdAst,
	cmdBacktraceName:        cmdBacktrace,
	cmdBuildGraphName:       cmdBuildGraph,
	cmdCallersName:          cmdCallers,
	cmdCalleesName:          cmdCallees,
	cmdCdName:               cmdCd,
	cmdExitName:             cmdExit,
	cmdFocusName:            cmdFocus,
	cmdIntraName:            cmdIntra,
	cmdListName:             cmdList,
	cmdLoadName:             cmdLoad,
	cmdLoadPackagesName:     cmdLoadPackages,
	cmdLoadWholeProgramName: cmdLoadWholeProgram,
	cmdLsName:               cmdLs,
	cmdMarkName:             cmdMark,
	cmdMayAliasName:         cmdMayAlias,
	cmdPackageName:          cmdPackage,
	cmdRebuildName:          cmdRebuild,
	cmdReconfigName:         cmdReconfig,
	cmdScanName:             cmdScan,
	cmdShowPackageName:      cmdShowPackage,
	cmdShowSsaName:          cmdShowSsa,
	cmdShowEscapeName:       cmdShowEscape,
	cmdMembersName:          cmdMembers,
	cmdRunDataflowName:      cmdRunDataflow,
	cmdRunPointerName:       cmdRunPointer,
	cmdShowDataflowName:     cmdShowDataflow,
	cmdSrcName:              cmdSrc,
	cmdSsaInstrName:         cmdSsaInstr,
	cmdSsaValueName:         cmdSsaValue,
	cmdStateName:            cmdState,
	cmdStatsName:            cmdStats,
	cmdSummaryName:          cmdSummary,
	cmdSummarizeName:        cmdSummarize,
	cmdTaintName:            cmdTaint,
	cmdTraceName:            cmdTrace,
	cmdUnfocusName:          cmdUnfocus,
	cmdWhereName:            cmdWhere,
}

// Run runs a simple CLI-based stdin-stdout server to allow us to explore the code.
func Run(flags tools.CommonFlags) {
	_, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting current directory\n")
		return
	}
	session := newSession(flags)
	loadedSess := session.loadConfig()
	if loadedSess.IsErr() {
		fmt.Fprintf(os.Stderr, "error loading config: %s\n", loadedSess.Error())
		os.Exit(-1)
	}

	// Start the command line tool with the state containing all the information
	run(session, flags.WithTest)
}

// run implements the command line tool, calling interpret for each command until the exit command is input
func run(sess *session, withTest bool) {
	oldState /* const */, err := term.MakeRaw(int(os.Stdin.Fd()))
	sess.termWidth, _, _ = term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	tt := term.NewTerminal(os.Stdin, "> ")
	sess.logger().SetAllOutput(tt)
	sess.logger().SetAllFlags(0) // no prefix
	tt.AutoCompleteCallback = autoCompleteOfAnalyzerState(sess)
	// if we get a SIGINT, we exit
	// Capture ctrl+c and exit by returning
	captureChan := make(chan os.Signal, 1)
	signal.Notify(captureChan, os.Interrupt)
	go exitOnReceive(captureChan, tt, oldState)
	// the infinite loop terminates when interpret returns true
	for {
		command, _ := tt.ReadLine()
		if interpret(tt, sess, strings.TrimSpace(command), withTest) {
			break
		}
	}
}

// interpret returns true to stop
func interpret(tt *term.Terminal, s *session, command string, withTest bool) bool {
	if command == "" {
		return false
	}
	cmd := ParseCommand(command)

	if cmd.Name == "" {
		return false
	}

	if f, ok := commands[cmd.Name]; ok {
		return f(tt, s, cmd, withTest)
	}
	if cmd.Name == cmdHelpName {
		cmdHelp(tt, s, cmd, withTest)
	} else {
		WriteErr(tt, "Command name %q not recognized.", cmd.Name)
		cmdHelp(tt, s, cmd, withTest)
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
