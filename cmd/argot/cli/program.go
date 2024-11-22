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

package cli

import (
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/escape"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

// cmdLoad implements the "load" command that loads a program into the tool.
// Once it updates the state.Args, it calls the rebuild command to build the program and the state.
func cmdLoad(tt *term.Terminal, c *dataflow.State, command Command, withTest bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : load new program\n", tt.Escape.Blue, cmdLoadName, tt.Escape.Reset)
		return false
	}

	if len(command.Args) == 0 {
		WriteErr(tt, "%s expects at least one argument.", cmdLoadName)
		return false
	}
	state.Args = command.Args
	return cmdRebuild(tt, c, command, withTest)
}

// cmdRebuild implements the rebuild command. It reloads the current program and rebuilds the state including the
// pointer analysis and callgraph information.
func cmdRebuild(tt *term.Terminal, c *dataflow.State, _ Command, withTest bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : rebuild the program being analyzed, including analyzer state.\n",
			tt.Escape.Blue, cmdRebuildName, tt.Escape.Reset)
		return false
	}

	writeFmt(tt, "Reading sources\n")
	// Load the program
	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     withTest,
		ApplyRewrites: true,
	}
	cfgs := config.NewState(c.GetConfig(), "", state.Args, loadOptions)
	pgrm := loadprogram.NewState(cfgs)
	ptrs := result.Bind(pgrm, ptr.NewState)
	newState, err := result.Bind(ptrs, dataflow.NewState).Value()
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
	copyState(newState, c)
	state.CurrentFunction = nil
	state.CurrentDataflowInformation = nil
	state.InitialPackages = newState.Packages
	return false
}

// copyState copies pointers in receiver into argument (shallow copy of everything except mutex).
// Do not use two copies in separate routines.
func copyState(from *dataflow.State, into *dataflow.State) {
	into.State = from.State
	into.Annotations = from.Annotations
	into.BoundingInfo = from.BoundingInfo
	into.Config = from.Config
	into.EscapeAnalysisState = from.EscapeAnalysisState
	into.FlowGraph = from.FlowGraph
	into.Globals = from.Globals
	into.ImplementationsByType = from.ImplementationsByType
	into.Logger = from.Logger
	into.PointerAnalysis = from.PointerAnalysis
	into.Program = from.Program
	into.Report = from.Report
	into.MethodKeys = from.MethodKeys
	// copy everything except mutex
}

// cmdReconfig implements the reconfig command and reloads the configuration file. If a new config file is specified,
// then it will load that new config file.
func cmdReconfig(tt *term.Terminal, c *dataflow.State, command Command, _ bool) bool {
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
