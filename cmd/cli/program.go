package main

import (
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"golang.org/x/term"
)

// cmdLoad implements the "load" command that loads a program into the tool.
// Once it updates the state.Args, it calls the rebuild command to build the program and the cache.
func cmdLoad(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
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

// cmdRebuild implements the rebuild command. It reloads the current program and rebuilds the cache including the
// pointer analysis and callgraph information.
func cmdRebuild(tt *term.Terminal, c *dataflow.Cache, _ Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : rebuild the program being analyzed, including cache.\n",
			tt.Escape.Blue, cmdRebuildName, tt.Escape.Reset)
		return false
	}

	writeFmt(tt, "Reading sources\n")
	// Load the program
	program, err := analysis.LoadProgram(nil, "", buildmode, state.Args)
	if err != nil {
		WriteErr(tt, "could not load program:\n%s\n", err)
		return false
	}
	// Build the cache with all analyses
	cache, err := dataflow.BuildFullCache(c.Logger, c.Config, program)
	if err != nil {
		WriteErr(tt, "error building cache: %s", err)
		return false
	}
	// Reassign cache elements
	c.PointerAnalysis = cache.PointerAnalysis
	c.FlowGraph = cache.FlowGraph
	c.DataFlowContracts = cache.DataFlowContracts
	c.Globals = cache.Globals
	c.Program = cache.Program
	//c = cache
	return false
}

// cmdReconfig implements the reconfig command and reloads the configuration file. If a new config file is specified,
// then it will load that new config file.
func cmdReconfig(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
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
		newConfig, err = config.Load(filename)
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
