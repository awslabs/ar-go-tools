package main

import (
	"os"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// serverState stores state information about the terminal. Not used to store information about the program
// being analyzed
type serverState struct {
	// the args (the path to the program to load
	Args []string

	ConfigPath string

	TermWidth int

	CurrentFunction *ssa.Function
}

var state = serverState{}

// Help command
func cmdHelp(tt *term.Terminal, c *dataflow.Cache, _ Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print help message\t", cmdHelpName, tt.Escape.Blue, tt.Escape.Reset)
		return false
	}
	writeFmt(tt, "Commands:\n")
	writeFmt(tt, "\t- %s%s%s : print this message\n", tt.Escape.Blue, cmdHelpName, tt.Escape.Reset)
	for _, cmd := range commands {
		cmd(tt, nil, Command{})
	}
	return false
}

// cmdState implements the "state?" command, which prints information about the current state of the tool
func cmdState(tt *term.Terminal, c *dataflow.Cache, _ Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print information about the current state\n",
			tt.Escape.Blue, cmdStateName, tt.Escape.Reset)
		return false
	}
	wd, _ := os.Getwd()
	fName := "none"
	if state.CurrentFunction != nil {
		fName = state.CurrentFunction.String()
	}
	writeFmt(tt, "Program path      : %s\n", strings.Join(state.Args, " "))
	writeFmt(tt, "Config path       : %s\n", state.ConfigPath)
	writeFmt(tt, "Working dir       : %s\n", wd)
	writeFmt(tt, "Focused function  : %s\n", fName)
	writeFmt(tt, "# functions       : %d\n", len(ssautil.AllFunctions(c.Program)))
	writeFmt(tt, "# summaries built : %d\n", len(c.FlowGraph.Summaries))
	writeFmt(tt, "flow graph built? : %t\n", c.FlowGraph.IsBuilt())
	return false
}

// cmdList shows all functions matching a given regex
func cmdList(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : list all functions matching provided regexes\n",
			tt.Escape.Blue, cmdListName, tt.Escape.Reset)
		return false
	}

	funcs := funcsMatchingCommand(tt, c, command)
	if len(funcs) == 0 {
		WriteSuccess(tt, "No matching function found.")
		return false
	}

	reachable := c.ReachableFunctions(false, false)

	WriteSuccess(tt, "Found %d matching functions:", len(funcs))
	WriteSuccess(tt, "[summarized?][reachable?] function name")

	numSummarized := 0
	numReachable := 0
	for _, fun := range funcs {
		_, hasSummary := c.FlowGraph.Summaries[fun]
		isReachable := reachable[fun]
		reachStr := "_"
		if isReachable {
			reachStr = "x"
			numReachable++
		}
		if hasSummary {
			writeFmt(tt, "%s[x][%s] %s%s\n", tt.Escape.Cyan, reachStr, fun.String(), tt.Escape.Reset)
			numSummarized++
		} else if isReachable {
			writeFmt(tt, "%s[_][%s] %s%s\n", tt.Escape.Magenta, reachStr, fun.String(), tt.Escape.Reset)
		} else {
			writeFmt(tt, "[_][%s] %s\n", reachStr, fun.String())
		}
	}
	WriteSuccess(tt, "(%d matching functions, %d reachable, %d summarized)", len(funcs),
		numReachable, numSummarized)
	return false
}
