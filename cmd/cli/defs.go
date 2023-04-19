package main

import (
	"go/token"
	"regexp"
	"strings"

	"github.com/awslabs/argot/analysis/dataflow"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const (
	cmdBuildGraphName   = "buildgraph"
	cmdCalleesName      = "callees"
	cmdCallersName      = "callers"
	cmdCdName           = "cd"
	cmdExitName         = "exit"
	cmdFocusName        = "focus"
	cmdIntraName        = "intra"
	cmdLoadName         = "load"
	cmdListName         = "list"
	cmdLsName           = "ls"
	cmdMayAliasName     = "mayalias"
	cmdHelpName         = "help"
	cmdPackageName      = "pkg"
	cmdRebuildName      = "rebuild"
	cmdReconfigName     = "reconfig"
	cmdScanName         = "scan"
	cmdShowSsaName      = "showssa"
	cmdShowEscapeName   = "showescape"
	cmdShowDataflowName = "showdataflow"
	cmdSsaInstrName     = "ssainstr"
	cmdSsaValueName     = "ssaval"
	cmdStateName        = "state?"
	cmdStatsName        = "stats"
	cmdSummarizeName    = "summarize"
	cmdSummaryName      = "summary"
	cmdTaintName        = "taint"
	cmdUnfocusName      = "unfocus"
	cmdWhereName        = "where"
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
func funcsMatchingCommand(tt *term.Terminal, c *dataflow.Cache, command Command) []*ssa.Function {
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
	return findFunc(c, r)
}

func findFunc(c *dataflow.Cache, target *regexp.Regexp) []*ssa.Function {
	var funcs []*ssa.Function
	for f := range ssautil.AllFunctions(c.Program) {
		if target.MatchString(f.String()) {
			funcs = append(funcs, f)
		}
	}
	return funcs
}

func regexErr(tt *term.Terminal, expr string, err error) {
	WriteErr(tt, "Error while compiling %s into regex:", expr)
	WriteErr(tt, "  %s", err)
}
