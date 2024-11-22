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
	"os"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/term"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// serverState stores state information about the terminal. Not used to store information about the program
// being analyzed
type serverState struct {
	// the args (the path to the program to load
	Args []string

	InitialPackages []*packages.Package

	ConfigPath string

	TermWidth int

	CurrentFunction *ssa.Function

	CurrentDataflowInformation *dataflow.FlowInformation
}

var state = serverState{}

// Help command
func cmdHelp(tt *term.Terminal, c *dataflow.State, _ Command, withTest bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print help message\t", cmdHelpName, tt.Escape.Blue, tt.Escape.Reset)
		return false
	}
	writeFmt(tt, "Commands:\n")
	writeFmt(tt, "\t- %s%s%s : print this message\n", tt.Escape.Blue, cmdHelpName, tt.Escape.Reset)
	for _, cmd := range commands {
		cmd(tt, nil, Command{}, withTest)
	}
	return false
}

// cmdState implements the "state?" command, which prints information about the current state of the tool
func cmdState(tt *term.Terminal, c *dataflow.State, _ Command, _ bool) bool {
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
	writeFmt(tt, "# functions       : %d\n", len(c.ReachableFunctions()))
	writeFmt(tt, "# summaries built : %d\n", len(c.FlowGraph.Summaries))
	writeFmt(tt, "flow graph built? : %t\n", c.FlowGraph.IsBuilt())
	return false
}

// cmdList shows all functions matching a given regex
func cmdList(tt *term.Terminal, c *dataflow.State, command Command, withTest bool) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : list all functions matching provided regexes\n",
			tt.Escape.Blue, cmdListName, tt.Escape.Reset)
		writeFmt(tt, "\t  Options:\n")
		writeFmt(tt, "\t    -r     list only reachable functions\n")
		writeFmt(tt, "\t    -s     list only summarized functions\n")
		writeFmt(tt, "\t    -h     print this help message\n")
		return false
	}

	if command.Flags["h"] {
		return cmdList(tt, nil, command, withTest)
	}

	funcs := funcsMatchingCommand(tt, c, command)
	if len(funcs) == 0 {
		WriteSuccess(tt, "No matching function found.")
		return false
	}

	reachable := c.ReachableFunctions()

	WriteSuccess(tt, "Found %d matching functions:", len(funcs))
	WriteSuccess(tt, "[summarized?][reachable?] function name")

	numSummarized := 0
	numReachable := 0
	for _, fun := range funcs {
		summary, hasSummary := c.FlowGraph.Summaries[fun]
		isReachable := reachable[fun]
		reachStr := "_"
		if isReachable {
			reachStr = "x"
			numReachable++
		} else if command.Flags["r"] {
			// -r means print only reachable functions
			continue
		}
		if hasSummary && summary.Constructed {
			writeFmt(tt, "%s[x][%s] %s%s\n", tt.Escape.Cyan, reachStr, fun.String(), tt.Escape.Reset)
			numSummarized++
		} else if isReachable && !command.Flags["s"] {
			writeFmt(tt, "%s[_][%s] %s%s\n", tt.Escape.Magenta, reachStr, fun.String(), tt.Escape.Reset)
		} else if !command.Flags["s"] && !command.Flags["r"] {
			writeFmt(tt, "[_][%s] %s\n", reachStr, fun.String())
		}
	}
	WriteSuccess(tt, "(%d matching functions, %d reachable, %d summarized)", len(funcs),
		numReachable, numSummarized)
	return false
}
