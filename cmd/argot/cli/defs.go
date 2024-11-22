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
	"go/token"
	"regexp"
	"slices"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

const (
	cmdBuildGraphName   = "buildgraph"
	cmdCalleesName      = "callees"
	cmdCallersName      = "callers"
	cmdCdName           = "cd"
	cmdExitName         = "exit"
	cmdFocusName        = "focus"
	cmdHelpName         = "help"
	cmdIntraName        = "intra"
	cmdLoadName         = "load"
	cmdListName         = "list"
	cmdLsName           = "ls"
	cmdMarkName         = "mark"
	cmdMayAliasName     = "mayalias"
	cmdPackageName      = "pkg"
	cmdRebuildName      = "rebuild"
	cmdReconfigName     = "reconfig"
	cmdScanName         = "scan"
	cmdShowDataflowName = "showdataflow"
	cmdShowEscapeName   = "showescape"
	cmdShowSsaName      = "showssa"
	cmdSsaInstrName     = "ssainstr"
	cmdSsaValueName     = "ssaval"
	cmdStateName        = "state?"
	cmdStatsName        = "stats"
	cmdSummarizeName    = "summarize"
	cmdSummaryName      = "summary"
	cmdTaintName        = "taint"
	cmdTraceName        = "trace"
	cmdUnfocusName      = "unfocus"
	cmdWhereName        = "where"
	cmdBacktraceName    = "backtrace"
	// Other constants

	// Summarize threshold puts a maximum size above which summary building filters are used
	summarizeThreshold = 5
)

// ************ HELPERS *********

// NameAndLoc hold a name and location together
type NameAndLoc struct {
	name string
	loc  token.Position
}

// funcsMatchingCommand returns the function matching the argument of the command or all functions if there
// is no argument
// Returns an empty list if any error is encountered
func funcsMatchingCommand(tt *term.Terminal, c *dataflow.State, command Command) []*ssa.Function {
	rString := ".*" // default is to match anything
	if len(command.Args) >= 1 {
		// otherwise build regex from arguments
		var x []string
		for _, arg := range command.Args {
			x = append(x, "("+arg+")")
		}
		rString = strings.Join(x, "|")
	}
	r, err := regexp.Compile(rString)
	if err != nil {
		regexErr(tt, rString, err)
		return []*ssa.Function{}
	}
	s := findFunc(c, r)
	slices.SortFunc(s, func(a, b *ssa.Function) int { return strings.Compare(a.String(), b.String()) })
	return s
}

func findFunc(c *dataflow.State, target *regexp.Regexp) []*ssa.Function {
	var funcs []*ssa.Function
	for f := range c.ReachableFunctions() {
		if target.MatchString(f.String()) {
			funcs = append(funcs, f)
		}
	}
	return funcs
}

func regexErr(tt *term.Terminal, expr string, err error) {
	WriteErr(tt, "Error while compiling %q into regex:", expr) // expr may come from config file
	WriteErr(tt, "  %s", err)                                  // err is safe
}
