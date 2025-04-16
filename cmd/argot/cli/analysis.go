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
	"bytes"
	"context"
	"go/ast"
	"go/printer"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/backtrace"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/escape"
	"github.com/awslabs/ar-go-tools/analysis/render"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

// Each "command" is a function func(state *dataflow.State, x string) that
// executes the command with state if state is not nil.
// If state is nil, then it should print its definition on stdout

// cmdShowSsa prints the SSA representation of all the function matching a given regex
func cmdShowSsa(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : print the ssa representation of a function.\n"+
			"\t  showssa regex prints the SSA representation of the function matching the regex\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdShowSsaName, tt.Escape.Reset)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdShowSsaName)
		return false
	}

	var b bytes.Buffer
	funcs, err := listContextFunc(tt, sess, command)
	if err != nil {
		WriteErr(tt, err.Error())
		return false
	}
	if len(funcs) == 0 {
		WriteErr(tt, "Need at least one function to show.")
		cmdShowSsa(tt, nil, command, withTest)
	}
	for _, f := range funcs {
		ssa.WriteFunction(&b, f)
		_, _ = b.WriteTo(tt)
		b.Reset()
	}
	return false
}

// cmdShowFuncType prints the type of all the functions matching a given regex
func cmdMembers(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : print the type of a function.\n"+
			"\t  %s regex prints the type of the function matching the regex\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdMembersName, tt.Escape.Reset, cmdMembersName)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdMembersName)
		return false
	}
	if len(command.Args) < 1 {
		WriteErr(tt, "%s expects a package regex", cmdMembersName)
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return false
	}

	// members needs a program
	prog := sess.loadProgram()
	if prog.IsErr() {
		WriteErr(tt, "Could not load program: %s", prog)
		return false
	}

	// Collect and print in alphabetical order
	members := []ssa.Member{}
	for _, p := range prog.Unwrap().Program.AllPackages() {
		if target.MatchString(p.String()) {
			for _, obj := range p.Members {
				members = append(members, obj)
			}
		}
	}
	slices.SortFunc(members, func(x ssa.Member, y ssa.Member) int { return strings.Compare(x.String(), y.String()) })
	for _, m := range members {
		switch m := m.(type) {
		case *ssa.Function:
			writeFmt(tt, "\t- function %s%s%s : %s\n", tt.Escape.Green, m.String(), tt.Escape.Reset, m.Type())
		case *ssa.Type:
			writeFmt(tt, "\t- type %s%s%s\n", tt.Escape.Blue, m.String(), tt.Escape.Reset)
			writeFmt(tt, "\t   | underlying %s\n", m.Type().Underlying())
			methods := prog.Unwrap().Program.MethodSets.MethodSet(m.Type())
			for i := range methods.Len() {
				mthd := methods.At(i)
				writeFmt(tt, "\t   | %s : %s\n", mthd.String(), mthd.Type())
			}
		case *ssa.NamedConst:
			writeFmt(tt, "\t- constant %s%s%s\n", tt.Escape.Yellow, m.String(), tt.Escape.Reset)
		case *ssa.Global:
			writeFmt(tt, "\t- global %s%s%s\n", tt.Escape.Magenta, m.String(), tt.Escape.Reset)
		}
	}
	return false
}

// cmdShowEscape prints the escape graph of all the function matching a given regex
func cmdShowEscape(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : print the escape graph of a function.\n"+ // safe %s (position string)
			"\t  %s regex prints the escape graph of function(s) matching the regex\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdShowEscapeName, tt.Escape.Reset, cmdShowEscapeName)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdShowEscapeName) // safe %s (position string)
		return false
	}

	var b bytes.Buffer
	funcs, err := listContextFunc(tt, sess, command)
	if err != nil {
		WriteErr(tt, err.Error())
		return false
	}
	if len(funcs) == 0 {
		WriteErr(tt, "Need at least one function to show.")
		cmdShowSsa(tt, nil, command, withTest)
	}
	for _, f := range funcs {
		eg := escape.EscapeSummary(f)
		b.WriteString(eg.Graphviz())
		_, _ = b.WriteTo(tt)
		b.Reset()
	}
	return false
}

// cmdShowDataflow builds and prints the inter-procedural dataflow graph.
// If on macOS, the command automatically renders an SVG and opens it in Safari.
func cmdShowDataflow(tt *term.Terminal, sess *session, _ Command, _ bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : build and print the inter-procedural dataflow graph of a program.\n"+
			"\t  showdataflow args prints the inter-procedural dataflow graph.\n"+
			"\t    on macOS, the command also renders an SVG of the graph and opens it in Safari\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdShowDataflowName, tt.Escape.Reset)
		writeFmt(tt, "\t  > %s main.go prog.go\n", cmdShowDataflowName)
		return false
	}

	// showDataflow needs dataflow state
	df := sess.loadDataflowAnalysis()
	if df.IsErr() {
		WriteErr(tt, "Could not load dataflow: %s", df)
		return false
	}
	c := df.Unwrap()

	// TODO the dataflow graph from the CLI is slightly different from the
	// `render` tool. This is because some function parameters are not being
	// visited. The refactor should address this.
	var err error
	c, err = render.BuildCrossFunctionGraph(c)
	if err != nil {
		WriteErr(tt, "Failed to build inter-procedural graph: %v\n", err)
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
			WriteErr(tt, "Failed to compile dot inter-procedural graph: %v\n", err)
			return false
		}

		openCtx, openCancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer openCancel()
		openCmd := exec.CommandContext(openCtx, "open", "-a", "Safari", svgFileName)
		if err := openCmd.Run(); err != nil {
			WriteErr(tt, "Failed to open dot inter-procedural graph SVG: %v\n", err)
			return false
		}
	}

	return false
}

// cmdSummary prints a specific function's summary, if it can be found
func cmdSummary(tt *term.Terminal, sess *session, command Command, _ bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : print the summary of the functions matching a regex\n",
			tt.Escape.Blue, cmdSummaryName, tt.Escape.Reset)
		return false
	}

	if len(command.Args) < 1 {
		if sess.currentFunction == nil {
			WriteErr(tt, "Not enough arguments, summary expects 1 argument")
		}
		// Print summary of focused function
		summary, ok := sess.hasSummary(sess.currentFunction)
		if summary != nil && ok {
			printSummary(tt, command, summary)
		} else {
			WriteErr(tt, "Focused function is not summarized")
		}
		return false
	}

	funcs, err := sess.funcsMatchingCommand(tt, command)
	if err != nil {
		WriteErr(tt, err.Error())
		return false
	}
	numSummaries := 0
	numFuncs := 0
	for _, fun := range funcs {
		numFuncs++
		summary, ok := sess.hasSummary(fun)
		if summary != nil && ok {
			numSummaries++
			printSummary(tt, command, summary)
		}
	}
	if numSummaries > 1 {
		WriteSuccess(tt, "(%d matching summaries)", numSummaries)
	} else if numSummaries == 1 {
		WriteSuccess(tt, "(1 matching summary)")
	} else {
		if numFuncs > 0 {
			WriteSuccess(tt, "No summaries found. Consider building summaries (summarize).")
		} else {
			WriteSuccess(tt, "No matching functions.")
		}
	}
	return false
}

// cmdShowSource prints the source (AST representation) of all the functions matching a given regex
func cmdSrc(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : print the source code of a function.\n"+
			"\t  src regex prints the AST representation of the function matching the regex\n"+
			"\t  Example:\n", tt.Escape.Blue, cmdSrcName, tt.Escape.Reset)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdSrcName)
		return false
	}

	funcs, err := listContextFunc(tt, sess, command)
	if err != nil {
		WriteErr(tt, err.Error())
		return false
	}
	if len(funcs) == 0 {
		WriteErr(tt, "Need at least one function to show source for.")
		cmdSrc(tt, nil, command, withTest)
	}
	for _, f := range funcs {
		astNode := f.Syntax()
		if astNode == nil {
			WriteErr(tt, "%s has no syntax.", formatutil.Bold(f.String()))
		} else {
			program, _ := sess.program() // program should be loaded at this point
			if program == nil {
				panic("internal error: program is missing")
			}
			WriteSuccess(tt, "<<< Source for %s", formatutil.Bold(f.String()))
			printer.Fprint(tt, program.Fset, astNode)
			writeFmt(tt, "\n")
			WriteSuccess(tt, "End of source for %s >>>", f.String())
			writeFmt(tt, "\n")
		}
	}
	return false
}

// cmdAst prints the AST structure of all the functions matching a given regex
func cmdAst(tt *term.Terminal, sess *session, command Command, withTest bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : print the ast of a function.\n"+
			"\t  %s regex prints the AST structure of the %sfunction%s matching the regex\n"+
			"\t  %s -file regex prints the AST structure of the %sfile%s matching the regex\n"+
			"\t  Example:\n",
			tt.Escape.Blue, cmdAstName, tt.Escape.Reset,
			cmdAstName, tt.Escape.Yellow, tt.Escape.Reset,
			cmdAstName, tt.Escape.Yellow, tt.Escape.Reset)
		writeFmt(tt, "\t  > %s command-line-arguments.main\n", cmdAstName)
		return false
	}

	if !sess.hasProgram() {
		WriteErr(tt, "Need a program to show the AST for.")
		WriteErr(tt, "You should at least loadprogam")
		cmdAst(tt, nil, command, withTest)
	}

	// Display the AST of a file?
	if command.Flags["file"] {
		files := findFiles(tt, sess, command)
		if len(files) == 0 {
			WriteErr(tt, "Need at least one file to show the AST for.")
			cmdAst(tt, nil, command, withTest)
		} else {
			for _, f := range files {
				filePath := sess.programOrPanic().Fset.Position(f.Pos()).Filename
				if f == nil {
					WriteErr(tt, "%s has no AST.", formatutil.Bold(filePath))
				} else {
					WriteSuccess(tt, "<<< AST of %s", formatutil.Bold(filePath))
					ast.Fprint(tt, sess.programOrPanic().Fset, f, nil)
					printer.Fprint(tt, sess.programOrPanic().Fset, f)
					writeFmt(tt, "\n")
					WriteSuccess(tt, "End of AST of %s >>>", filePath)
					writeFmt(tt, "\n")
				}
			}
		}
		return false
	}
	// Display the AST of a function
	funcs, err := listContextFunc(tt, sess, command)
	if err != nil {
		WriteErr(tt, err.Error())
		return false
	}
	if len(funcs) == 0 {
		WriteErr(tt, "Need at least one function to show the AST for.")
		cmdAst(tt, nil, command, withTest)
	}
	for _, f := range funcs {
		astNode := f.Syntax()
		if astNode == nil {
			WriteErr(tt, "%s has no AST.", formatutil.Bold(f.String()))
		} else {
			WriteSuccess(tt, "<<< AST of %s", formatutil.Bold(f.String()))
			ast.Fprint(tt, sess.programOrPanic().Fset, astNode, nil)
			printer.Fprint(tt, sess.programOrPanic().Fset, astNode)
			writeFmt(tt, "\n")
			WriteSuccess(tt, "End of AST of %s >>>", f.String())
			writeFmt(tt, "\n")
		}
	}
	return false
}

// cmdSummarize runs the intra-procedural analysis.
func cmdSummarize(tt *term.Terminal, sess *session, command Command, _ bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s : run the intra-procedural analysis. If a function is provided, "+
			"run only\n", tt.Escape.Blue, cmdSummarizeName, tt.Escape.Reset)
		writeFmt(tt, "\t   on the provided function\n")
		writeFmt(tt, "\t   This will build dataflow summaries for all specified functions.\n")
		writeFmt(tt, "\t   -force flag will force summarization and bypass filters on reachable functions.\n")
		return false
	}

	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	isForced := command.Flags["force"]

	// ensure dataflow state
	res := sess.loadDataflowAnalysis()
	if res.IsErr() {
		WriteErr(tt, "Could not load dataflow: %s", res)
		return false
	}
	c := res.Unwrap()

	if len(command.Args) < 1 {
		// Running the intra-procedural analysis on all functions
		WriteSuccess(tt, "Running intra-procedural analysis on all functions")
		createCounter := 0
		buildCounter := 0

		shouldBuildSummary := func(c *dataflow.State, f *ssa.Function) bool {
			b := isForced || dataflow.ShouldBuildSummary(c, f)
			if b {
				buildCounter++
			}
			createCounter++
			return b
		}
		dataflow.RunIntraProceduralPass(c, numRoutines, dataflow.IntraAnalysisParams{
			ShouldBuildSummary: shouldBuildSummary,
			ShouldTrack:        dataflow.IsNodeOfInterest,
		})
		WriteSuccess(tt, "%d summaries created, %d built", createCounter, buildCounter)
	} else {
		// Running the intra-procedural analysis on a single function, if it can be found
		regex, err := regexp.Compile(command.Args[0])
		if err != nil {
			regexErr(tt, command.Args[0], err)
			return false
		}
		funcs, err := sess.findFunc(regex)
		if err != nil {
			WriteErr(tt, err.Error())
			return false
		}
		WriteSuccess(tt, "Running intra-procedural analysis on functions matching %s", command.Args[0])

		// Depending on the summaries threshold and the number of matched functions, different filters are used.
		// If len(funcs) > summarizeThreshold, the filter used is similar to the one used in the taint analysis.
		buildCounter := 0

		var shouldBuildSummary func(c *dataflow.State, f *ssa.Function) bool
		if len(funcs) > summarizeThreshold {
			// above a certain threshold, we use the general analysis filters on what to summarize, unless -force has
			// been specified
			shouldBuildSummary = summarizeWithDefaultParams(tt, funcs, isForced, &buildCounter)
		} else {
			// below that threshold, all functions that match are summarize.
			// useful for testing.
			shouldBuildSummary = alwaysSummarize(funcs, &buildCounter)
		}

		// Run the analysis with the filter.
		dataflow.RunIntraProceduralPass(c, numRoutines, dataflow.IntraAnalysisParams{
			ShouldBuildSummary: shouldBuildSummary,
			ShouldTrack:        dataflow.IsNodeOfInterest,
		})
		// Insert the summaries, i.e. only updated the summaries that have been computed and do not discard old ones

		WriteSuccess(tt, "%d summaries created, %d built.", len(funcs), buildCounter)
		if buildCounter == 0 {
			WriteSuccess(tt, "The queried functions may not be reachable?")
			WriteSuccess(tt, "If less than %d functions match the query, then all reachable "+
				"matching functions will be summarized", summarizeThreshold)
		}
	}
	return false
}

func summarizeWithDefaultParams(tt *term.Terminal, funcs []*ssa.Function, isForced bool,
	buildCounter *int) func(*dataflow.State, *ssa.Function) bool {
	WriteSuccess(tt, "(more than %d functions matching, other config-defined filters are in use)",
		summarizeThreshold)
	shouldBuildSummary := func(c *dataflow.State, f *ssa.Function) bool {
		b := isForced || (!summaries.IsStdFunction(f) &&
			summaries.IsUserDefinedFunction(f) &&
			funcutil.Contains(funcs, f) &&
			!c.HasExternalContractSummary(f))
		if b {
			*buildCounter++
		}
		return b
	}
	return shouldBuildSummary
}

func alwaysSummarize(funcs []*ssa.Function, buildCounter *int) func(*dataflow.State, *ssa.Function) bool {
	shouldBuildSummary := func(_ *dataflow.State, f *ssa.Function) bool {
		b := funcutil.Contains(funcs, f)
		if b {
			*buildCounter++
		}
		return b
	}
	return shouldBuildSummary
}

// cmdTaint runs the taint analysis
func cmdTaint(tt *term.Terminal, sess *session, _ Command, _ bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s: run the taint analysis with parameters in config.\n",
			tt.Escape.Blue, cmdTaintName, tt.Escape.Reset)
		writeFmt(tt, "\t   Flow graph must be built first with `%s%s%s`.\n",
			tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		return false
	}
	c := sess.loadDataflowAnalysis()
	if c.IsErr() {
		WriteErr(tt, "Failed to load dataflow analysis: %v", c)
		return false
	}
	// load dataflow state
	if !c.Unwrap().FlowGraph.IsBuilt() {
		WriteErr(tt, "The inter-procedural dataflow graph is not built!")
		WriteErr(tt, "Please run `%s` before calling `taint`.", cmdBuildGraphName)
		return false
	}
	for _, ts := range c.Unwrap().Config.TaintTrackingProblems {
		c.Unwrap().FlowGraph.RunVisitorOnEntryPoints(
			taint.NewVisitor(&ts),
			dataflow.ScanningSpec{
				MarkCallArgsLikeCall: ts.SourceTaintsArgs,
				IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
					return dataflow.IsSourceNode(c.Unwrap(), &ts, node)
				},
			},
		)
	}
	return false
}

// cmdBacktrace runs the backtrace analysis.
func cmdBacktrace(tt *term.Terminal, sess *session, _ Command, _ bool) bool {
	if sess == nil {
		writeFmt(tt, "\t- %s%s%s: run the backtrace analysis with parameters in config.\n",
			tt.Escape.Blue, cmdBacktraceName, tt.Escape.Reset)
		writeFmt(tt, "\t   Flow graph must be built first with `%s%s%s`.\n",
			tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		return false
	}

	res := sess.loadDataflowAnalysis()
	if res.IsErr() {
		WriteErr(tt, "Failed to load dataflow analysis: %v", res)
		return false
	}
	c := res.Unwrap()

	if !c.FlowGraph.IsBuilt() {
		WriteErr(tt, "The inter-procedural dataflow graph is not built!")
		WriteErr(tt, "Please run `%s` before calling `backtrace`.", cmdBuildGraphName)
		return false
	}

	var traces []backtrace.Trace
	for _, ps := range c.Config.SlicingProblems {
		visitor := backtrace.NewVisitor(ps)
		c.FlowGraph.RunVisitorOnEntryPoints(
			visitor,
			dataflow.ScanningSpec{
				IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
					return dataflow.IsBacktraceNode(c, &ps, node)
				}})
		for _, tr := range visitor.Traces {
			traces = append(traces, tr...)
		}
	}

	writeFmt(tt, "Traces:\n")
	for _, trace := range traces {
		writeFmt(tt, "%v\n", trace)
	}

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
	writeFmt(tt, "%s:\n", formatutil.Yellow("Nodes"))
	var regexFilter *regexp.Regexp
	if filter, ok := command.NamedArgs["f"]; ok {
		var err error
		regexFilter, err = regexp.Compile(filter)
		if err != nil {
			regexErr(tt, filter, err)
			return
		}
	}
	summary.ForAllNodes(func(n dataflow.GraphNode) {
		if regexFilter != nil && !regexFilter.MatchString(n.String()) {
			return
		}
		writeFmt(tt, "\t %s\n", n)
	})
	summary.PrettyPrint(true, tt, regexFilter)
}

func listContextFunc(tt *term.Terminal, sess *session, command Command) ([]*ssa.Function, error) {
	if len(command.Args) < 1 {
		if sess.currentFunction != nil {
			return []*ssa.Function{sess.currentFunction}, nil
		}
		return []*ssa.Function{}, nil
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return []*ssa.Function{}, nil
	}

	return sess.findFunc(target)
}

// findFiles finds the ast file in the program loaded.
// You should ensure that the  LPState of the session has been loaded, otherwise
// this function will just return an empty list.
func findFiles(tt *term.Terminal, sess *session, command Command) []*ast.File {
	if sess.lpState == nil {
		return []*ast.File{}
	}
	if len(command.Args) < 1 {
		WriteErr(tt, "Need a regex to match files.")
		return []*ast.File{}
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(tt, command.Args[0], err)
		return []*ast.File{}
	}
	files := []*ast.File{}
	for _, p := range sess.lpState.Packages {
		for _, f := range p.Syntax {
			fpos := f.Pos()
			if !fpos.IsValid() {
				continue
			}
			filename := sess.lpState.Program.Fset.File(fpos).Name()
			if target.MatchString(filename) {
				files = append(files, f)
			}
		}
	}
	return files
}
