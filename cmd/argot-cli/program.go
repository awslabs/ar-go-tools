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
	"strings"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/escape"
	"golang.org/x/term"
)

// cmdLoad implements the "load" command that loads a program into the tool.
// Once it updates the state.Args, it calls the rebuild command to build the program and the state.
func cmdLoad(tt *term.Terminal, c *dataflow.AnalyzerState, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : load new program\n", tt.Escape.Blue, cmdLoadName, tt.Escape.Reset)
		return false
	}

	if len(command.Args) == 0 {
		WriteErr(tt, "%s expects at least one argument.", cmdLoadName)
		return false
	}
	state.Args = command.Args
	return cmdRebuild(tt, c, command)
}

// cmdRebuild implements the rebuild command. It reloads the current program and rebuilds the state including the
// pointer analysis and callgraph information.
func cmdRebuild(tt *term.Terminal, c *dataflow.AnalyzerState, _ Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : rebuild the program being analyzed, including analyzer state.\n",
			tt.Escape.Blue, cmdRebuildName, tt.Escape.Reset)
		return false
	}

	writeFmt(tt, "Reading sources\n")
	// Load the program
	program, pkgs, err := analysis.LoadProgram(nil, "", buildmode, *withTest, state.Args)
	if err != nil {
		WriteErr(tt, "could not load program:\n%s\n", err)
		return false
	}
	// Build the newState with all analyses
	newState, err := dataflow.NewInitializedAnalyzerState(program, pkgs, c.Logger, c.Config)
	if err != nil {
		WriteErr(tt, "error building analyzer state: %s", err)
		WriteErr(tt, "state is left unchanged")
		return false
	}
	// Optional step: running the escape analysis
	if c.Config.UseEscapeAnalysis {
		err := escape.InitializeEscapeAnalysisState(newState)
		if err != nil {
			WriteErr(tt, "error running escape analysis: %s", err)
			WriteErr(tt, "state is left unchanged")
			return false
		}
	}
	// Reassign state elements
	newState.CopyTo(c)
	state.CurrentFunction = nil
	state.CurrentDataflowInformation = nil
	state.InitialPackages = pkgs
	return false
}

// cmdReconfig implements the reconfig command and reloads the configuration file. If a new config file is specified,
// then it will load that new config file.
func cmdReconfig(tt *term.Terminal, c *dataflow.AnalyzerState, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : load the specified config file\n",
			tt.Escape.Blue, cmdReconfigName, tt.Escape.Reset)
		writeFmt(tt, "\t    Example: %s config.yaml\n", cmdReconfigName)
		return false
	}

	var newConfig *config.Config
	var err error

	if len(command.Args) < 1 {
		// No arguments: reload the current config file.
		newConfig, err = config.LoadGlobal()
	} else {
		// Argument specified: set state.ConfigPath to the new config file's path, if the file exists
		filename := strings.TrimSpace(command.Args[0])
		newConfig, err = config.LoadFromFiles(filename)
		if err == nil {
			config.SetGlobalConfig(filename)
			state.ConfigPath = filename
		}
	}

	if err != nil {
		WriteErr(tt, "Error loading config file.")
		WriteErr(tt, "%s", err)
		return false
	}

	c.Config = newConfig
	if len(command.Args) < 1 {
		WriteSuccess(tt, "Reloaded config from disk.")
	} else {
		WriteSuccess(tt, "Loaded new config!")
	}
	return false
}
