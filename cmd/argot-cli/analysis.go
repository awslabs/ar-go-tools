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
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"time"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/escape"
	"github.com/awslabs/argot/analysis/functional"
	"github.com/awslabs/argot/analysis/summaries"
	"github.com/awslabs/argot/analysis/taint"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

// Each "command" is a function func(*dataflow.Cache, string) that
// executes the command with cache if cache is not nil.
// If cache is nil, then it should print its definition on stdout

// cmdShowSsa prints the SSA representation of all the function matching a given regex
func cmdShowSsa(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print the ssa representation of a function.\n"+
			"\t  showssa regex prints the SSA representation of the function matching the regex\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdShowSsaName, tt.Escape.Reset)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdShowSsaName)
		return false
	}

	if len(command.Args) < 1 {
		if state.CurrentFunction != nil {
			var b bytes.Buffer
			ssa.WriteFunction(&b, state.CurrentFunction)
			_, _ = b.WriteTo(tt)
			b.Reset()
		} else {
			WriteErr(tt, "Need at least one function to show.")
			cmdShowSsa(tt, nil, command)
		}
		return false
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
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

// cmdShowEscape prints the escape graph of all the function matching a given regex
func cmdShowEscape(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print the escape graph of a function.\n"+
			"\t  %s regex prints the escape graph of function(s) matching the regex\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdShowEscapeName, tt.Escape.Reset, cmdShowEscapeName)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdShowEscapeName)
		return false
	}

	if len(command.Args) < 1 {
		if state.CurrentFunction != nil {
			var b bytes.Buffer
			nodes, eg := escape.EscapeSummary(state.CurrentFunction)
			b.WriteString(eg.Graphviz(nodes))
			_, _ = b.WriteTo(tt)
			b.Reset()
		} else {
			WriteErr(tt, "Need at least one function to show.")
			cmdShowSsa(tt, nil, command)
		}
		return false
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}
	var b bytes.Buffer
	funcs := findFunc(c, target)
	for _, f := range funcs {
		nodes, eg := escape.EscapeSummary(f)
		b.WriteString(eg.Graphviz(nodes))
		_, _ = b.WriteTo(tt)
		b.Reset()
	}
	return false
}

// cmdShowDataflow builds and prints the cross-function dataflow graph.
// If on macOS, the command automatically renders an SVG and opens it in Safari.
func cmdShowDataflow(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : build and print the cross-function dataflow graph of a program.\n"+
			"\t  showdataflow args prints the cross-function dataflow graph.\n"+
			"\t    on macOS, the command also renders an SVG of the graph and opens it in Safari\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdShowDataflowName, tt.Escape.Reset)
		writeFmt(tt, "\t  > %s main.go prog.go\n", cmdShowDataflowName)
		return false
	}

	// TODO the dataflow graph from the CLI is slightly different from the
	// `render` tool. This is because some function parameters are not being
	// visited. The refactor should address this.
	var err error
	c, err = analysis.BuildCrossFunctionGraph(c)
	if err != nil {
		WriteErr(tt, "Failed to build cross-function graph: %v\n", err)
		return false
	}
	var b bytes.Buffer
	c.FlowGraph.Print(&b)

	tt.Write(b.Bytes())
	if runtime.GOOS == "darwin" {
		dotFile, err := os.CreateTemp(os.TempDir(), "*.dot")
		if err != nil {
			WriteErr(tt, "Failed to create temp file: %v\n", dotFile.Name())
			return false
		}
		WriteSuccess(tt, " to file %v", dotFile.Name())
		dotFile.Write(b.Bytes())

		dotCtx, dotCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dotCancel()
		svgFileName := dotFile.Name() + ".svg"
		dotCmd := exec.CommandContext(dotCtx, "dot", "-Tsvg", dotFile.Name(), "-o", svgFileName)
		if err := dotCmd.Run(); err != nil {
			WriteErr(tt, "Failed to compile dot cross-function graph: %v\n", err)
			return false
		}

		openCtx, openCancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer openCancel()
		openCmd := exec.CommandContext(openCtx, "open", "-a", "Safari", svgFileName)
		if err := openCmd.Run(); err != nil {
			WriteErr(tt, "Failed to open dot cross-function graph SVG: %v\n", err)
			return false
		}
	}

	return false
}

// cmdSummary prints a specific function's summary, if it can be found
func cmdSummary(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : print the summary of the functions matching a regex\n",
			tt.Escape.Blue, cmdSummaryName, tt.Escape.Reset)
		return false
	}

	if len(command.Args) < 1 {
		if state.CurrentFunction == nil {
			WriteErr(tt, "Not enough arguments, summary expects 1 argument")
		}
		// Print summary of focused function
		summary := c.FlowGraph.Summaries[state.CurrentFunction]
		if summary != nil {
			printSummary(tt, command, summary)
		} else {
			WriteErr(tt, "Focused function is not summarized")
		}
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
			printSummary(tt, command, summary)
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
func cmdSummarize(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : run the single-function analysis. If a function is provided, "+
			"run only\n", tt.Escape.Blue, cmdSummarizeName, tt.Escape.Reset)
		writeFmt(tt, "\t   on the provided function\n")
		writeFmt(tt, "\t   This will build dataflow summaries for all specified functions.\n")
		return false
	}

	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	isForced := command.Flags["force"]

	if len(command.Args) < 1 {
		// Running the single-function analysis on all functions
		WriteSuccess(tt, "Running single-function analysis on all functions")
		createCounter := 0
		buildCounter := 0
		shouldCreateSummary := func(f *ssa.Function) bool {
			b := isForced || taint.ShouldCreateSummary(f)
			if b {
				createCounter++
			}
			return b
		}
		shouldBuildSummary := func(c *dataflow.Cache, f *ssa.Function) bool {
			b := isForced || taint.ShouldBuildSummary(c, f)
			if b {
				buildCounter++
			}
			return b
		}
		res := analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
			Cache:               c,
			NumRoutines:         numRoutines,
			ShouldCreateSummary: shouldCreateSummary,
			ShouldBuildSummary:  shouldBuildSummary,
			IsEntrypoint:        taint.IsSourceNode,
		})
		c.FlowGraph.InsertSummaries(res.FlowGraph)
		WriteSuccess(tt, "%d summaries created, %d built", createCounter, buildCounter)
	} else {
		// Running the single-function analysis on a single function, if it can be found
		regex, err := regexp.Compile(command.Args[0])
		if err != nil {
			regexErr(tt, command.Args[0], err)
			return false
		}
		funcs := findFunc(c, regex)
		WriteSuccess(tt, "Running single-function analysis on functions matching %s", command.Args[0])

		// Depending on the summaries threshold and the number of matched functions, different filters are used.
		// If len(funcs) > summarizeThreshold, the filter used is similar to the one used in the taint analysis.
		createCounter := 0
		buildCounter := 0
		var shouldCreateSummary func(f *ssa.Function) bool
		var shouldBuildSummary func(c *dataflow.Cache, f *ssa.Function) bool
		if len(funcs) > summarizeThreshold {
			// above a certain threshold, we use the general analysis filters on what to summarize, unless -force has
			// been specified
			WriteSuccess(tt, "(more than %d functions matching, other config-defined filters are in use)",
				summarizeThreshold)
			shouldCreateSummary = func(f *ssa.Function) bool {
				b := isForced || (!summaries.IsStdFunction(f) &&
					summaries.IsUserDefinedFunction(f) &&
					functional.Contains(funcs, f) &&
					!c.HasExternalContractSummary(f))
				if b {
					createCounter++
				}
				return b
			}
			shouldBuildSummary = func(c *dataflow.Cache, f *ssa.Function) bool {
				b := isForced || (!summaries.IsStdFunction(f) &&
					summaries.IsUserDefinedFunction(f) &&
					functional.Contains(funcs, f) &&
					!c.HasExternalContractSummary(f))
				if b {
					buildCounter++
				}
				return b
			}
		} else {
			// below that threshold, all functions that match are summarize.
			// useful for testing.
			shouldCreateSummary = func(f *ssa.Function) bool {
				b := functional.Contains(funcs, f)
				if b {
					createCounter++
				}
				return b
			}
			shouldBuildSummary = func(_ *dataflow.Cache, f *ssa.Function) bool {
				b := functional.Contains(funcs, f)
				if b {
					buildCounter++
				}
				return b
			}
		}

		// Run the analysis with the filter.
		res := analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
			Cache:               c,
			NumRoutines:         numRoutines,
			ShouldCreateSummary: shouldCreateSummary,
			ShouldBuildSummary:  shouldBuildSummary,
			IsEntrypoint:        taint.IsSourceNode,
		})
		// Insert the summaries, i.e. only updated the summaries that have been computed and do not discard old ones
		c.FlowGraph.InsertSummaries(res.FlowGraph)
		WriteSuccess(tt, "%d summaries created, %d built.", createCounter, buildCounter)
		if createCounter == 0 {
			WriteSuccess(tt, "The queried functions may not be reachable?")
			WriteSuccess(tt, "If less than %d functions match the query, then all reachable "+
				"matching functions will be summarized", summarizeThreshold)
		}
	}
	return false
}

// cmdTaint runs the taint analysis
func cmdTaint(tt *term.Terminal, c *dataflow.Cache, _ Command) bool {
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
	c.FlowGraph.RunCrossFunctionPass(taint.NewVisitor(nil), dataflow.IsSourceFunction)
	return false
}

func printSummary(tt *term.Terminal, command Command, summary *dataflow.SummaryGraph) {
	if _, mustFilter := command.NamedArgs["filter"]; mustFilter {
		WriteErr(tt, "TODO : implement filtering graphs to show only relevant edges.")
	}
	WriteSuccess(tt, "Found summary of %s:", summary.Parent.String())
	if !summary.Constructed {
		writeFmt(tt, "  %s(not built)%s\n", tt.Escape.Red, tt.Escape.Reset)
	}
	if summary.IsInterfaceContract {
		writeFmt(tt, "  (is interface contract)\n")
	}
	summary.PrettyPrint(true, tt)
}