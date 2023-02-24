package main

import (
	"bytes"
	"flag"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/functional"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/summaries"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/taint"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const (
	cmdBuildGraphName = "buildgraph"
	cmdCallersName    = "callers"
	cmdExitName       = "exit"
	cmdListName       = "list"
	cmdLsName         = "ls"
	cmdHelpName       = "help"
	cmdRebuildName    = "rebuild"
	cmdReconfigName   = "reconfig"
	cmdShowName       = "show"
	cmdSummarizeName  = "summarize"
	cmdSummaryName    = "summary"
	cmdTaintName      = "taint"
)

// Each "command" is a function func(*dataflow.Cache, string) that
// executes the command with cache if cache is not nil.
// If cache is nil, then it should print its definition on stdout

// cmdBuildGraph builds the cross-function flow graph given the current summaries
func cmdBuildGraph(tt *term.Terminal, c *dataflow.Cache, _ string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : build the cross-function flow graph.\n",
			tt.Escape.Blue, cmdBuildGraphName, tt.Escape.Reset)
		writeFmt(tt, "\t   Summaries must be built first with `%s%s%s`.\n",
			tt.Escape.Yellow, cmdSummarizeName, tt.Escape.Reset)
		return false
	}
	if len(c.FlowGraph.Summaries) == 0 {
		WriteErr(tt, "No summaries present. Did you run `summarize`?")
		return false
	}
	c.FlowGraph.BuildGraph()
	WriteSuccess(tt, "Built cross function flow graph.")
	return false
}

// cmdCallers shows the callers of a given summarized function
func cmdCallers(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: shows the callers of a given summarized function.\n",
			tt.Escape.Blue, cmdCallersName, tt.Escape.Reset)
		writeFmt(tt, "    %s will only be accurate after `%s%s%s`.\n",
			cmdCallersName, tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		return false
	}
	for _, f := range funcsMatchingCommand(tt, c, command) {
		if summary, hasSummary := c.FlowGraph.Summaries[f]; hasSummary {
			WriteSuccess(tt, "Callers of %s:", f.String())
			for _, callsite := range summary.Callsites {
				writeFmt(tt, "\t- %s\n", callsite.String())
				writeFmt(tt, "\t position: %s\n", callsite.Position(c).String())
			}
		}
	}
	return false
}

// Exit command
func cmdExit(tt *term.Terminal, c *dataflow.Cache, _ string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : exit the program\n", tt.Escape.Blue, cmdExitName, tt.Escape.Reset)
		return false
	}
	writelnEscape(tt, tt.Escape.Magenta, "Exiting...")
	return true
}

// cmdList shows all functions matching a given regex
func cmdList(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : list all functions matching a regex\n",
			tt.Escape.Blue, cmdListName, tt.Escape.Reset)
		return false
	}

	funcs := funcsMatchingCommand(tt, c, command)
	if len(funcs) == 0 {
		WriteSuccess(tt, "No matching function found.")
		return false
	}

	WriteSuccess(tt, "Found %d matching functions:", len(funcs))
	numSummarized := 0
	for _, fun := range funcs {
		_, hasSummary := c.FlowGraph.Summaries[fun]
		if hasSummary {
			writeFmt(tt, "%s[x] %s%s\n", tt.Escape.Cyan, fun.String(), tt.Escape.Reset)
			numSummarized++
		} else {
			writeFmt(tt, "[_] %s\n", fun.String())
		}
	}
	WriteSuccess(tt, "(%d matching functions, %d summarized)", len(funcs), numSummarized)
	return false
}

func cmdLs(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : list files in directory\n", tt.Escape.Blue, cmdLsName, tt.Escape.Reset)
		return false
	}
	var extraPath string
	if ps := strings.Split(command, " "); len(ps) > 1 {
		extraPath = ps[1]
	}
	entries, err := os.ReadDir(path.Join(state.Wd, extraPath))
	if err != nil {
		WriteErr(tt, "error listing directory %s: %s", state.Wd, err)
		return false
	}

	WriteSuccess(tt, "Entries in %s:", path.Join(state.Wd, extraPath))
	for _, entry := range entries {
		writeFmt(tt, "%s\n", entry.Name())
	}
	return false
}

// Help command
func cmdHelp(tt *term.Terminal, c *dataflow.Cache, _ string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print help message\t", cmdHelpName, tt.Escape.Blue, tt.Escape.Reset)
		return false
	}
	writeFmt(tt, "Commands:\n")
	writeFmt(tt, "\t- %s%s%s : print this message\n", tt.Escape.Blue, cmdHelpName, tt.Escape.Reset)
	for _, cmd := range commands {
		cmd(tt, nil, "")
	}
	return false
}

func cmdRebuild(tt *term.Terminal, c *dataflow.Cache, _ string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : rebuild the program being analyzed, including cache.\n",
			tt.Escape.Blue, cmdRebuildName, tt.Escape.Reset)
		return false
	}

	writeFmt(tt, "Reading sources\n")
	// Load the program
	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
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

func cmdReconfig(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : load the specified config file\n",
			tt.Escape.Blue, cmdReconfigName, tt.Escape.Reset)
		writeFmt(tt, "\t    Example: %s config.yaml\n", cmdReconfigName)
		return false
	}

	var newConfig *config.Config
	var err error

	parts := strings.Split(command, " ")
	if len(parts) < 2 {
		newConfig, err = config.LoadGlobal()
	} else {
		filename := strings.TrimSpace(parts[1])
		newConfig, err = config.Load(filename)
		if err == nil {
			config.SetGlobalConfig(filename)
		}
	}

	if err != nil {
		WriteErr(tt, "Error loading config file.")
		WriteErr(tt, "%s", err)
		return false
	}

	c.Config = newConfig
	WriteSuccess(tt, "Loaded new config!")
	return false
}

// cmdShow prints the SSA representation of all the function matching a given regex
func cmdShow(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print the ssa representation of a function.\n"+
			"\t  show regex prints the SSA representation of the function matching the regex\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdShowName, tt.Escape.Reset)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdShowName)
		return false
	}
	parts := strings.Split(command, " ")
	if len(parts) < 2 {
		cmdShow(tt, nil, command)
		return false
	}
	target, err := regexp.Compile(parts[1])
	if err != nil {
		regexErr(tt, parts[1], err)
		return false
	}
	var b bytes.Buffer
	funcs := findFunc(c, target)
	for _, f := range funcs {
		ssa.WriteFunction(&b, f)
		_, _ = b.WriteTo(tt)
		b.Reset()
	}
	return false
}

// cmdSummary prints a specific function's summary, if it can be found
func cmdSummary(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print the summary of the functions matching a regex\n",
			tt.Escape.Blue, cmdSummaryName, tt.Escape.Reset)
		return false
	}

	parts := strings.Split(command, " ")
	if len(parts) == 1 {
		WriteErr(tt, "Not enough arguments, summary expects 1 argument")
		return false
	}

	funcs := funcsMatchingCommand(tt, c, command)
	numSummaries := 0
	numFuncs := 0
	for _, fun := range funcs {
		numFuncs++
		summary := c.FlowGraph.Summaries[fun]
		if summary != nil {
			numSummaries++
			WriteSuccess(tt, "Found summary of %s:", fun.String())
			summary.Print(tt)
		}
	}
	if numSummaries > 0 {
		WriteSuccess(tt, "(%d matching summaries)", numSummaries)
	} else {
		if numFuncs > 0 {
			WriteSuccess(tt, "No summaries found. Consider building summaries (summarize).")
		} else {
			WriteSuccess(tt, "No matching functions.")
		}
	}
	return false
}

// cmdSummarize runs the single-function analysis.
func cmdSummarize(tt *term.Terminal, c *dataflow.Cache, command string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : run the single-function analysis. If a function is provided, "+
			"run only\n", tt.Escape.Blue, cmdSummarizeName, tt.Escape.Reset)
		writeFmt(tt, "\t   on the provided function\n")
		writeFmt(tt, "\t   This will build dataflow summaries for all specified functions.\n")
		return false
	}
	parts := strings.Split(command, " ")
	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	if len(parts) < 2 {
		// Running the single-function analysis on all functions
		WriteSuccess(tt, "Running single-function analysis on all functions")
		counter := 0
		shouldBuildSummary := func(f *ssa.Function) bool {
			b := !summaries.IsStdFunction(f) && summaries.IsUserDefinedFunction(f)
			if b {
				counter++
			}
			return b
		}
		res := analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
			Cache:              c,
			NumRoutines:        0,
			ShouldBuildSummary: shouldBuildSummary,
			IsSourceNode:       taint.IsSourceNode,
			IsSinkNode:         taint.IsSinkNode,
		})
		c.FlowGraph.InsertSummaries(res.FlowGraph)
		WriteSuccess(tt, "%d summarized", counter)
	} else {
		// Running the single-function analysis on a single function, if is can be found
		fregex, err := regexp.Compile(parts[1])
		if err != nil {
			regexErr(tt, parts[1], err)
		}
		funcs := findFunc(c, fregex)
		WriteSuccess(tt, "Running single-function analysis on functions matching %s", parts[1])
		counter := 0
		shouldBuildSummary := func(f *ssa.Function) bool {
			b := !summaries.IsStdFunction(f) && summaries.IsUserDefinedFunction(f) && functional.Contains(funcs, f)
			if b {
				counter++
			}
			return b
		}
		res := analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
			Cache:              c,
			NumRoutines:        0,
			ShouldBuildSummary: shouldBuildSummary,
			IsSourceNode:       taint.IsSourceNode,
			IsSinkNode:         taint.IsSinkNode,
		})
		c.FlowGraph.InsertSummaries(res.FlowGraph)
		WriteSuccess(tt, "%d summarized", counter)
	}
	return false
}

// cmdTaint runs the taint analysis
func cmdTaint(tt *term.Terminal, c *dataflow.Cache, _ string) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: run the taint analysis with parameters in config.\n",
			tt.Escape.Blue, cmdTaintName, tt.Escape.Reset)
		writeFmt(tt, "\t   Flow graph must be built first with `%s%s%s`.\n",
			tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		return false
	}
	if !c.FlowGraph.IsBuilt() {
		WriteErr(tt, "The cross-function dataflow graph is not built!")
		WriteErr(tt, "Please run `%s` before calling `taint`.", cmdBuildGraphName)
		return false
	}
	dataFlows := map[ssa.Instruction]map[ssa.Instruction]bool{}
	c.FlowGraph.RunCrossFunctionPass(dataFlows, taint.VisitFromSource, nil)
	return false
}

// ************ HELPERS *********

// funcsMatchingCommand returns the function matching the argument of the command or all functions if there
// is no argument
// Returns an empty list if any error is encountered
func funcsMatchingCommand(tt *term.Terminal, c *dataflow.Cache, command string) []*ssa.Function {
	rString := ".*" // default is to match anything
	if args := strings.Split(command, " "); len(args) > 1 {
		rString = args[1] // otherwise match the first argument of the command
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
