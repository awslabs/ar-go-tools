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

// A CommandDefinition defines a command both for the cli and for the MCP server.
type CommandDefinition struct {
	// Name of the command
	Name string
	// Description of the command
	Description string
	// InputSchema of the command (for the MCP server)
	InputSchema tools.MCPInputSchema
	// Function to run the command
	Function func(tt *term.Terminal, s *Session, command Command, withTest bool) bool
}

// ToMCPToolDefinition returns the MCP tool definition of the command.
func (c CommandDefinition) ToMCPToolDefinition() tools.MCPTool {
	return tools.MCPTool{
		Name:        c.Name,
		Description: c.Description,
		InputSchema: c.InputSchema,
	}
}

// Commands lists all the commands available in the cli.
var Commands = map[string]CommandDefinition{
	cmdAstName: {
		Name:        cmdAstName,
		Description: "Print the AST of a function or file",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function or file names",
				},
				"file": map[string]interface{}{
					"type":        "boolean",
					"description": "Print AST of file instead of function",
				},
			},
			Required: []string{"regex"},
		},
		Function: cmdAst,
	},
	cmdBacktraceName: {
		Name:        cmdBacktraceName,
		Description: "Run the backtrace analysis with parameters in config",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdBacktrace,
	},
	cmdBuildGraphName: {
		Name:        cmdBuildGraphName,
		Description: "Build the inter-procedural dataflow graph",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdBuildGraph,
	},
	cmdCallersName: {
		Name:        cmdCallersName,
		Description: "Show the callers of a function",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
			},
			Required: []string{"regex"},
		},
		Function: cmdCallers,
	},
	cmdCalleesName: {
		Name:        cmdCalleesName,
		Description: "Show callees of a function",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
			},
			Required: []string{"regex"},
		},
		Function: cmdCallees,
	},
	cmdCdName: {
		Name:        cmdCdName,
		Description: "Move to relative directory",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"directory": map[string]interface{}{
					"type":        "string",
					"description": "Directory path to change to",
				},
			},
			Required: []string{"directory"},
		},
		Function: cmdCd,
	},
	cmdExitName: {
		Name:        cmdExitName,
		Description: "Exit the program",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdExit,
	},
	cmdFocusName: {
		Name:        cmdFocusName,
		Description: "Focus on a specific function",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
			},
			Required: []string{"regex"},
		},
		Function: cmdFocus,
	},
	cmdIntraName: {
		Name:        cmdIntraName,
		Description: "Run intra-procedural analysis",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdIntra,
	},
	cmdListName: {
		Name:        cmdListName,
		Description: "List functions matching a regex",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
			},
			Required: []string{},
		},
		Function: cmdList,
	},
	cmdLoadName: {
		Name:        cmdLoadName,
		Description: "Load new program",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"packages": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Package paths to load",
				},
			},
			Required: []string{"packages"},
		},
		Function: cmdLoad,
	},
	cmdLoadPackagesName: {
		Name:        cmdLoadPackagesName,
		Description: "Load packages",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"packages": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Package paths to load",
				},
				"with_types": map[string]interface{}{
					"type":        "boolean",
					"description": "Load packages with types",
				},
			},
			Required: []string{"packages"},
		},
		Function: cmdLoadPackages,
	},
	cmdLoadWholeProgramName: {
		Name:        cmdLoadWholeProgramName,
		Description: "Load the arguments as whole program",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdLoadWholeProgram,
	},
	cmdLsName: {
		Name:        cmdLsName,
		Description: "List files in directory",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to list (defaults to current directory)",
				},
			},
			Required: []string{},
		},
		Function: cmdLs,
	},
	cmdMarkName: {
		Name:        cmdMarkName,
		Description: "Mark functions or values",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match names",
				},
			},
			Required: []string{"regex"},
		},
		Function: cmdMark,
	},
	cmdMayAliasName: {
		Name:        cmdMayAliasName,
		Description: "Check if values may alias",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"values": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Values to check for aliasing",
				},
			},
			Required: []string{"values"},
		},
		Function: cmdMayAlias,
	},
	cmdPackageName: {
		Name:        cmdPackageName,
		Description: "Show package information",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match package names",
				},
			},
			Required: []string{},
		},
		Function: cmdPackage,
	},
	cmdRebuildName: {
		Name:        cmdRebuildName,
		Description: "Rebuild the program being analyzed",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdRebuild,
	},
	cmdReconfigName: {
		Name:        cmdReconfigName,
		Description: "Load the specified config file",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"config_file": map[string]interface{}{
					"type":        "string",
					"description": "Path to config file",
				},
			},
			Required: []string{"config_file"},
		},
		Function: cmdReconfig,
	},
	cmdScanName: {
		Name:        cmdScanName,
		Description: "Scan for patterns in code",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"pattern": map[string]interface{}{
					"type":        "string",
					"description": "Pattern to scan for",
				},
			},
			Required: []string{"pattern"},
		},
		Function: cmdScan,
	},
	cmdShowPackageName: {
		Name:        cmdShowPackageName,
		Description: "Show package details",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match package names",
				},
			},
			Required: []string{},
		},
		Function: cmdShowPackage,
	},
	cmdShowSsaName: {
		Name:        cmdShowSsaName,
		Description: "Print the SSA representation of a function",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
			},
			Required: []string{},
		},
		Function: cmdShowSsa,
	},
	cmdShowEscapeName: {
		Name:        cmdShowEscapeName,
		Description: "Print the escape graph of a function",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
			},
			Required: []string{},
		},
		Function: cmdShowEscape,
	},
	cmdMembersName: {
		Name:        cmdMembersName,
		Description: "Print the type of a function",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match package names",
				},
			},
			Required: []string{"regex"},
		},
		Function: cmdMembers,
	},
	cmdRunDataflowName: {
		Name:        cmdRunDataflowName,
		Description: "Run the dataflow analysis",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdRunDataflow,
	},
	cmdRunPointerName: {
		Name:        cmdRunPointerName,
		Description: "Run the pointer analysis",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdRunPointer,
	},
	cmdShowDataflowName: {
		Name:        cmdShowDataflowName,
		Description: "Build and print the inter-procedural dataflow graph",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdShowDataflow,
	},
	cmdSrcName: {
		Name:        cmdSrcName,
		Description: "Print the source code of a function",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
			},
			Required: []string{},
		},
		Function: cmdSrc,
	},
	cmdSsaInstrName: {
		Name:        cmdSsaInstrName,
		Description: "Show SSA instruction details",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"instruction": map[string]interface{}{
					"type":        "string",
					"description": "SSA instruction to examine",
				},
			},
			Required: []string{"instruction"},
		},
		Function: cmdSsaInstr,
	},
	cmdSsaValueName: {
		Name:        cmdSsaValueName,
		Description: "Show SSA value details",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"value": map[string]interface{}{
					"type":        "string",
					"description": "SSA value to examine",
				},
			},
			Required: []string{"value"},
		},
		Function: cmdSsaValue,
	},
	cmdStateName: {
		Name:        cmdStateName,
		Description: "Show current analysis state",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdState,
	},
	cmdStatsName: {
		Name:        cmdStatsName,
		Description: "Show program statistics",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdStats,
	},
	cmdSummaryName: {
		Name:        cmdSummaryName,
		Description: "Print the internal dataflow summary of functions matching a regex",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
				"filter": map[string]interface{}{
					"type":        "string",
					"description": "Filter for summary display",
				},
			},
			Required: []string{},
		},
		Function: cmdSummary,
	},
	cmdSummarizeName: {
		Name:        cmdSummarizeName,
		Description: "Run the intra-procedural dataflow analysis",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names (optional)",
				},
				"force": map[string]interface{}{
					"type":        "boolean",
					"description": "Force summarization and bypass filters",
				},
			},
			Required: []string{},
		},
		Function: cmdSummarize,
	},
	cmdTaintName: {
		Name:        cmdTaintName,
		Description: "Run the taint analysis with parameters in config file",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdTaint,
	},
	cmdTraceName: {
		Name:        cmdTraceName,
		Description: "Trace the flow of a specific SSA value in the program",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"target": map[string]interface{}{
					"type":        "string",
					"description": "Target to trace",
				},
			},
			Required: []string{"target"},
		},
		Function: cmdTrace,
	},
	cmdUnfocusName: {
		Name:        cmdUnfocusName,
		Description: "Remove focus from current function",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdUnfocus,
	},
	cmdWhereName: {
		Name:        cmdWhereName,
		Description: "Show location information",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"target": map[string]interface{}{
					"type":        "string",
					"description": "Target to locate",
				},
			},
			Required: []string{"target"},
		},
		Function: cmdWhere,
	},
}

// Run runs a simple CLI-based stdin-stdout server to allow us to explore the code.
func Run(flags tools.CommonFlags) {
	_, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting current directory\n")
		return
	}
	session := NewSession(flags)
	loadedSess := session.LoadConfig()
	if loadedSess.IsErr() {
		fmt.Fprintf(os.Stderr, "error loading config: %s\n", loadedSess.Error())
		os.Exit(-1)
	}

	// Start the command line tool with the state containing all the information
	run(session, flags.WithTest)
}

// run implements the command line tool, calling interpret for each command until the exit command is input
func run(sess *Session, withTest bool) {
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
func interpret(tt *term.Terminal, s *Session, command string, withTest bool) bool {
	if command == "" {
		return false
	}
	cmd := ParseCommand(command)

	if cmd.Name == "" {
		return false
	}

	if cmdDef, ok := Commands[cmd.Name]; ok {
		return cmdDef.Function(tt, s, cmd, withTest)
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
		writeFmt(tt, "%s", formatutil.Red("Caught SIGINT, exiting!"))
		term.Restore(int(os.Stdin.Fd()), oldState)
		os.Exit(0)
	}
}
