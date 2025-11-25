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
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/term"
	"os"
	"os/signal"
	"strings"
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
	// SchemaTranslation is the translation from the input schema to the command schema
	SchemaTranslation func(props map[string]interface{}) (Command, error)
	// Function to run the command
	Function func(o Outputter, s *Session, command Command, withTest bool) bool
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
	CmdAstName: {
		Name:        toolAstName,
		Description: "Print the AST of a function or file (shows detailed AST)",
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
		// command is ast [-file] regex
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			fileFlag := false
			if file, ok := props["file"]; ok {
				fileFlag, ok = file.(bool)
				if !ok {
					return Command{}, fmt.Errorf("file must be a boolean")
				}
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{"file": fileFlag},
			}, nil
		},
		Function: cmdAst,
	},
	CmdBacktraceName: {
		Name:        toolBacktraceName,
		Description: "Run the backtrace analysis with parameters in config",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdBacktrace,
	},
	CmdBuildGraphName: {
		Name:        toolBuildGraphName,
		Description: "Build the inter-procedural dataflow graph",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdBuildGraph,
	},
	CmdCallersName: {
		Name:        toolCallersName,
		Description: "Show the callers of a function. Uses the best analysis loaded (e.g. pointer when loaded).",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdCallers,
	},
	CmdCalleesName: {
		Name:        toolCalleesName,
		Description: "Show callees of a function. Uses the best analysis loaded (e.g. pointer when loaded).",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdCallees,
	},
	CmdCdName: {
		Name:        toolCdName,
		Description: "Move to relative directory (system command)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			directory, ok := props["directory"].(string)
			if !ok {
				return Command{}, fmt.Errorf("directory must be provided")
			}
			return Command{
				Args:  []string{directory},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdCd,
	},
	CmdExitName: {
		Name:        toolExitName,
		Description: "Exit the program (system command, terminates the server).",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdExit,
	},
	CmdFocusName: {
		Name:        toolFocusName,
		Description: "Focus on a specific function, so you can inspect ssa values, instructions, aliases...",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdFocus,
	},
	CmdIntraName: {
		Name:        toolIntraName,
		Description: "Run intra-procedural dataflow analysis (requires focused function)",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdIntra,
	},
	CmdListName: {
		Name: toolListName,
		Description: "List functions matching a regex (golang), " +
			"with options on listing reachable and summarized functions.",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"regex": map[string]interface{}{
					"type":        "string",
					"description": "Regex to match function names",
				},
				"reachable_only": map[string]interface{}{
					"type":        "boolean",
					"description": "List only reachable functions",
				},
				"summarized_only": map[string]interface{}{
					"type":        "boolean",
					"description": "List only summarized functions",
				},
			},
			Required: []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex := ""
			if regexObj, ok := props["regex"]; ok {
				if regexStr, ok := regexObj.(string); ok {
					regex = regexStr
				} else {
					return Command{}, fmt.Errorf("regex must be a string")
				}
			}
			flags := map[string]bool{}
			if reachableOnly, ok := props["reachable_only"]; ok {
				if reachableBool, ok := reachableOnly.(bool); ok {
					flags["r"] = reachableBool
				} else {
					return Command{}, fmt.Errorf("reachable_only must be a boolean")
				}
			}
			if summarizedOnly, ok := props["summarized_only"]; ok {
				if summarizedBool, ok := summarizedOnly.(bool); ok {
					flags["s"] = summarizedBool
				} else {
					return Command{}, fmt.Errorf("summarized_only must be a boolean")
				}
			}
			args := []string{}
			if regex != "" {
				args = []string{regex}
			}
			return Command{
				Args:  args,
				Flags: flags,
			}, nil
		},
		Function: cmdList,
	},
	CmdLoadName: {
		Name:        toolLoadName,
		Description: "Load new program from package paths. This resets the analysis state (pointer, dataflow, ..)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			packagesObj, ok := props["packages"]
			if !ok {
				return Command{}, fmt.Errorf("packages must be provided")
			}
			packages, ok := packagesObj.([]interface{})
			if !ok {
				return Command{}, fmt.Errorf("packages must be an array")
			}
			args := make([]string, len(packages))
			for i, pkg := range packages {
				args[i], ok = pkg.(string)
				if !ok {
					return Command{}, fmt.Errorf("package must be a string")
				}
			}
			return Command{
				Args:  args,
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdLoad,
	},
	CmdLoadPackagesName: {
		Name: toolLoadPackagesName,
		Description: "Load Go packages with optional type information for inspection." +
			" This is faster than loading a whole program.",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			packagesObj, ok := props["packages"]
			if !ok {
				return Command{}, fmt.Errorf("packages must be provided")
			}
			packages, ok := packagesObj.([]interface{})
			if !ok {
				return Command{}, fmt.Errorf("packages must be an array")
			}
			args := make([]string, len(packages))
			for i, pkg := range packages {
				args[i], ok = pkg.(string)
				if !ok {
					return Command{}, fmt.Errorf("package must be a string")
				}
			}
			flags := map[string]bool{}
			if withTypes, ok := props["with_types"]; ok {
				if withTypesBool, ok := withTypes.(bool); ok {
					flags["t"] = withTypesBool
				} else {
					return Command{}, fmt.Errorf("with_types must be a boolean")
				}
			}
			return Command{
				Args:  args,
				Flags: flags,
			}, nil
		},
		Function: cmdLoadPackages,
	},
	CmdLoadWholeProgramName: {
		Name:        toolLoadWholeProgramName,
		Description: "Load and build complete SSA program from the current program path (show the state to see)",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdLoadWholeProgram,
	},
	CmdLsName: {
		Name:        toolLsName,
		Description: "List files in directory (system command)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			path := "."
			if pathObj, ok := props["path"]; ok {
				if pathStr, ok := pathObj.(string); ok {
					path = pathStr
				} else {
					return Command{}, fmt.Errorf("path must be a string")
				}
			}
			return Command{
				Args:  []string{path},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdLs,
	},
	CmdMarkName: {
		Name:        toolMarkName,
		Description: "Show dataflow marks and associated instructions (requires focused function)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdMark,
	},
	CmdMayAliasName: {
		Name:        toolMayAliasName,
		Description: "Check if values may alias (requires focused function)",
		InputSchema: tools.MCPInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"values": map[string]interface{}{
					"type":        "string",
					"description": "Regex matching values to check for aliasing.",
				},
			},
			Required: []string{"values"},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			if values, ok := props["values"].(string); ok {
				return Command{
					Args:  []string{values},
					Flags: map[string]bool{},
				}, nil
			}
			return Command{}, fmt.Errorf("values must be a string")
		},
		Function: cmdMayAlias,
	},
	CmdPackageName: {
		Name:        toolPackageName,
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
	CmdRebuildName: {
		Name:        toolRebuildName,
		Description: "Rebuild the program being analyzed. Re-initializes the complex analyses!",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		Function: cmdRebuild,
	},
	CmdReconfigName: {
		Name:        toolReconfigName,
		Description: "Reload current config or load new configuration file. Re-initializes all the analyses.",
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
	CmdScanName: {
		Name:        toolScanName,
		Description: "Scan AST for identifiers and types matching regex patterns.",
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
	CmdShowPackageName: {
		Name:        toolShowPackageName,
		Description: "Show detailed information about a loaded package including files and imports.",
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
	CmdShowSsaName: {
		Name:        toolShowSsaName,
		Description: "Print the SSA representation of a function.",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdShowSsa,
	},
	CmdShowEscapeName: {
		Name:        toolShowEscapeName,
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdShowEscape,
	},
	CmdMembersName: {
		Name:        toolMembersName,
		Description: "Print package members (functions, types, constants, globals) matching a regex",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdMembers,
	},
	CmdRunDataflowName: {
		Name:        toolRunDataflowName,
		Description: "Run the dataflow analysis (advanced analysis)",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdRunDataflow,
	},
	CmdRunPointerName: {
		Name:        toolRunPointerName,
		Description: "Run the pointer analysis (advanced analysis, use to get callees)",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdRunPointer,
	},
	CmdShowDataflowName: {
		Name:        toolShowDataflowName,
		Description: "Build and print the inter-procedural dataflow graph (advanced analysis, run summarize first)",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdShowDataflow,
	},
	CmdSrcName: {
		Name:        toolSrcName,
		Description: "Print the source code of a function.",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdSrc,
	},
	CmdSsaInstrName: {
		Name:        toolSsaInstrName,
		Description: "Show SSA instruction details (requires focused function)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			instruction, ok := props["instruction"].(string)
			if !ok || instruction == "" {
				return Command{}, fmt.Errorf("instruction must be a non-empty string")
			}
			return Command{
				Args:  []string{instruction},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdSsaInstr,
	},
	CmdSsaValueName: {
		Name:        toolSsaValueName,
		Description: "Show SSA value details (requires focused function)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			value, ok := props["value"].(string)
			if !ok || value == "" {
				return Command{}, fmt.Errorf("value must be a non-empty string")
			}
			return Command{
				Args:  []string{value},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdSsaValue,
	},
	CmdStateName: {
		Name:        toolStateName,
		Description: "Show current analysis state.",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdState,
	},
	CmdStatsName: {
		Name:        toolStatsName,
		Description: "Display comprehensive program statistics including SSA, defers, and closure usage.",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdStats,
	},
	CmdSummaryName: {
		Name: toolSummaryName,
		Description: "Print the internal dataflow summary of functions matching a regex. " +
			"You should have run summarize on that function first (or on all functions)." +
			"Running this may be very expensive!",
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
			Required: []string{"regex"},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			regex, ok := props["regex"].(string)
			if !ok || regex == "" {
				return Command{}, fmt.Errorf("regex must be a non-empty string")
			}
			namedArgs := map[string]string{}
			filter, ok := props["filter"].(string)
			if ok {
				namedArgs["f"] = filter
			}
			return Command{
				Args:      []string{regex, filter},
				Flags:     map[string]bool{},
				NamedArgs: namedArgs,
			}, nil
		},
		Function: cmdSummary,
	},
	CmdSummarizeName: {
		Name: toolSummarizeName,
		Description: "Build dataflow summaries for functions using intra-procedural analysis." +
			"Depending on internal parameters, running the tool without arguments may only instantiate " +
			"the summaries without building them.",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			forceFlag := false
			if force, ok := props["force"]; ok {
				if forceBool, ok := force.(bool); ok {
					forceFlag = forceBool
				} else {
					return Command{}, fmt.Errorf("force flag must be a boolean")
				}
			}
			regex := ""
			regexObj, ok := props["regex"]
			if ok {
				if regexStr, ok := regexObj.(string); ok {
					regex = regexStr
				} else {
					return Command{}, fmt.Errorf("regex must be a string")
				}
			}
			return Command{
				Args:  []string{regex},
				Flags: map[string]bool{"force": forceFlag},
			}, nil
		},
		Function: cmdSummarize,
	},
	CmdTaintName: {
		Name: toolTaintName,
		Description: "Run the taint analysis with parameters in config file. Does nothing if no config file has been" +
			"loaded, or the config file does not define any taint analysis problem.",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdTaint,
	},
	CmdTraceName: {
		Name:        toolTraceName,
		Description: "Trace dataflow paths for a specific SSA value through the program (advanced debugging analysis)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			target, ok := props["target"].(string)
			if !ok || target == "" {
				return Command{}, fmt.Errorf("target must be a non-empty string")
			}
			return Command{
				Args:  []string{target},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdTrace,
	},
	CmdUnfocusName: {
		Name:        toolUnfocusName,
		Description: "Remove focus from current function (requires focused function)",
		InputSchema: tools.MCPInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
			Required:   []string{},
		},
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			return Command{
				Args:  []string{},
				Flags: map[string]bool{},
			}, nil
		},
		Function: cmdUnfocus,
	},
	CmdWhereName: {
		Name:        toolWhereName,
		Description: "Show source file location of functions or current focused function (requires focused function)",
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
		SchemaTranslation: func(props map[string]interface{}) (Command, error) {
			target, ok := props["target"].(string)
			if !ok || target == "" {
				return Command{}, fmt.Errorf("target must be a non-empty string")
			}
			return Command{
				Args:  []string{target},
				Flags: map[string]bool{},
			}, nil
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
	tt := term.NewTerminal(os.Stdin, "> ")
	o := NewTerminalOutputter(tt)
	session := NewSession(flags, true)
	oldState /* const */, err := term.MakeRaw(int(os.Stdin.Fd()))
	session.termWidth, _, _ = term.GetSize(int(os.Stdin.Fd()))

	session.logger().SetAllOutput(tt)
	session.logger().SetAllFlags(0) // no prefix
	tt.AutoCompleteCallback = autoCompleteOfAnalyzerState(session)
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	loadedSess := session.LoadConfig(o, true)
	if loadedSess.IsErr() {
		fmt.Fprintf(os.Stderr, "error loading config: %s\n", loadedSess.Error())
		os.Exit(-1)
	}

	// Start the command line tool with the state containing all the information
	run(o, session, oldState, flags.WithTest)
}

// run implements the command line tool, calling interpret for each command until the exit command is input
func run(o Outputter, sess *Session, oldState *term.State, withTest bool) {
	// if we get a SIGINT, we exit
	// Capture ctrl+c and exit by returning
	captureChan := make(chan os.Signal, 1)
	signal.Notify(captureChan, os.Interrupt)
	go exitOnReceive(captureChan, o, oldState)
	// the infinite loop terminates when interpret returns true
	for {
		if o.tt != nil {
			command, _ := o.tt.ReadLine()
			if interpret(o, sess, strings.TrimSpace(command), withTest) {
				break
			}
		}
	}
}

// interpret returns true to stop
func interpret(o Outputter, s *Session, command string, withTest bool) bool {
	if command == "" {
		return false
	}
	cmd := ParseCommand(command)

	if cmd.Name == "" {
		return false
	}

	if cmdDef, ok := Commands[cmd.Name]; ok {
		return cmdDef.Function(o, s, cmd, withTest)
	}
	if cmd.Name == CmdHelpName {
		cmdHelp(o, s, cmd, withTest)
	} else {
		o.WriteErr("Command name %q not recognized.", cmd.Name)
		cmdHelp(o, s, cmd, withTest)
	}
	return false
}

func exitOnReceive(c chan os.Signal, o Outputter, oldState *term.State) {
	for range c {
		o.Write("%s", formatutil.Red("Caught SIGINT, exiting!"))
		term.Restore(int(os.Stdin.Fd()), oldState)
		os.Exit(0)
	}
}
