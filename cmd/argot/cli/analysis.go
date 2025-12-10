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
	"golang.org/x/tools/go/ssa"
)

// Each "command" is a function func(state *dataflow.State, x string) that
// executes the command with state if state is not nil.
// If state is nil, then it should print its definition on stdout

// cmdShowSsa prints the SSA representation of all the function matching a given regex
func cmdShowSsa(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : print the ssa representation of a function.\n"+
			"\t  showssa regex prints the SSA representation of the function matching the regex\n"+
			"\t  Example:\n", o.EscBlue(), CmdShowSsaName, o.EscReset())
		o.Write("\t  > %s command-line-arguments.main\n", CmdShowSsaName)
		return false
	}

	var b bytes.Buffer
	funcs, err := listContextFunc(o, sess, command)
	if err != nil {
		o.WriteErr("%s", err.Error())
		return false
	}
	if len(funcs) == 0 {
		o.WriteErr("Need at least one function to show.")
		cmdShowSsa(o, nil, command, withTest)
	}
	for _, f := range funcs {
		ssa.WriteFunction(&b, f)
		_, _ = b.WriteTo(o.Writer())
		b.Reset()
	}
	return false
}

// cmdShowFuncType prints the type of all the functions matching a given regex
func cmdMembers(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : print the type of a function.\n"+
			"\t  %s regex prints the type of the function matching the regex\n"+
			"\t  Example:\n", o.EscBlue(), CmdMembersName, o.EscReset(), CmdMembersName)
		o.Write("\t  > %s command-line-arguments.main\n", CmdMembersName)
		return false
	}
	if len(command.Args) < 1 {
		o.WriteErr("%s expects a package regex", CmdMembersName)
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
		return false
	}

	// members needs a program
	prog := sess.loadProgram(o)
	if prog.IsErr() {
		o.WriteErr("Could not load program: %s", prog)
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
			o.Write("\t- function %s%s%s : %s\n", o.EscGreen(), m.String(), o.EscReset(), m.Type())
		case *ssa.Type:
			o.Write("\t- type %s%s%s\n", o.EscBlue(), m.String(), o.EscReset())
			o.Write("\t   | underlying %s\n", m.Type().Underlying())
			methods := prog.Unwrap().Program.MethodSets.MethodSet(m.Type())
			for i := range methods.Len() {
				mthd := methods.At(i)
				o.Write("\t   | %s : %s\n", mthd.String(), mthd.Type())
			}
		case *ssa.NamedConst:
			o.Write("\t- constant %s%s%s\n", o.EscYellow(), m.String(), o.EscReset())
		case *ssa.Global:
			o.Write("\t- global %s%s%s\n", o.EscMagenta(), m.String(), o.EscReset())
		}
	}
	return false
}

// cmdShowEscape prints the escape graph of all the function matching a given regex
func cmdShowEscape(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : print the escape graph of a function.\n"+ // safe %s (position string)
			"\t  %s regex prints the escape graph of function(s) matching the regex\n"+
			"\t  Example:\n", o.EscBlue(), CmdShowEscapeName, o.EscReset(), CmdShowEscapeName)
		o.Write("\t  > %s command-line-arguments.main\n", CmdShowEscapeName) // safe %s (position string)
		return false
	}

	var b bytes.Buffer
	funcs, err := listContextFunc(o, sess, command)
	if err != nil {
		o.WriteErr("%s", err.Error())
		return false
	}
	if len(funcs) == 0 {
		o.WriteErr("Need at least one function to show.")
		cmdShowSsa(o, nil, command, withTest)
	}
	for _, f := range funcs {
		eg := escape.EscapeSummary(f)
		b.WriteString(eg.Graphviz())
		_, _ = b.WriteTo(o.Writer())
		b.Reset()
	}
	return false
}

// cmdShowDataflow builds and prints the inter-procedural dataflow graph.
// If on macOS, the command automatically renders an SVG and opens it in Safari.
func cmdShowDataflow(o Outputter, sess *Session, _ Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : build and print the inter-procedural dataflow graph of a program.\n"+
			"\t  showdataflow args prints the inter-procedural dataflow graph.\n"+
			"\t    on macOS, the command also renders an SVG of the graph and opens it in Safari\n"+
			"\t  Example:\n", o.EscBlue(), CmdShowDataflowName, o.EscReset())
		o.Write("\t  > %s main.go prog.go\n", CmdShowDataflowName)
		return false
	}

	// showDataflow needs dataflow state
	df := sess.loadDataflowAnalysis(o)
	if df.IsErr() {
		o.WriteErr("Could not load dataflow: %s", df)
		return false
	}
	c := df.Unwrap()

	// TODO the dataflow graph from the CLI is slightly different from the
	// `render` tool. This is because some function parameters are not being
	// visited. The refactor should address this.
	var err error
	c, err = render.BuildCrossFunctionGraph(c)
	if err != nil {
		o.WriteErr("Failed to build inter-procedural graph: %v\n", err)
		return false
	}
	var b bytes.Buffer
	c.FlowGraph.Print(&b)

	o.Write(b.String())
	if runtime.GOOS == "darwin" {
		dotFile, err := os.CreateTemp(os.TempDir(), "*.dot")
		if err != nil {
			o.WriteErr("Failed to create temp file: %v\n", dotFile.Name())
			return false
		}
		o.WriteSuccess(" to file %v", dotFile.Name())
		dotFile.Write(b.Bytes())

		dotCtx, dotCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dotCancel()
		svgFileName := dotFile.Name() + ".svg"
		dotCmd := exec.CommandContext(dotCtx, "dot", "-Tsvg", dotFile.Name(), "-o", svgFileName)
		if err := dotCmd.Run(); err != nil {
			o.WriteErr("Failed to compile dot inter-procedural graph: %v\n", err)
			return false
		}

		openCtx, openCancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer openCancel()
		openCmd := exec.CommandContext(openCtx, "open", "-a", "Safari", svgFileName)
		if err := openCmd.Run(); err != nil {
			o.WriteErr("Failed to open dot inter-procedural graph SVG: %v\n", err)
			return false
		}
	}

	return false
}

// cmdSummary prints a specific function's summary, if it can be found
func cmdSummary(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : print the summary of the functions matching a regex\n",
			o.EscBlue(), CmdSummaryName, o.EscReset())
		return false
	}

	if len(command.Args) < 1 {
		if sess.currentFunction == nil {
			o.WriteErr("Not enough arguments, summary expects 1 argument")
		}
		// Print summary of focused function
		summary, ok := sess.hasSummary(sess.currentFunction)
		if summary != nil && ok {
			printSummary(o, command, summary)
		} else {
			o.WriteErr("Focused function is not summarized")
		}
		return false
	}

	funcs, err := sess.funcsMatchingCommand(o, command)
	if err != nil {
		o.WriteErr("%s", err.Error())
		return false
	}
	numSummaries := 0
	numFuncs := 0
	for _, fun := range funcs {
		numFuncs++
		summary, ok := sess.hasSummary(fun)
		if summary != nil && ok {
			numSummaries++
			printSummary(o, command, summary)
		}
	}
	if numSummaries > 1 {
		o.WriteSuccess("(%d matching summaries)", numSummaries)
	} else if numSummaries == 1 {
		o.WriteSuccess("(1 matching summary)")
	} else {
		if numFuncs > 0 {
			o.WriteSuccess("No summaries found. Consider building summaries (summarize).")
		} else {
			o.WriteSuccess("No matching functions.")
		}
	}
	return false
}

// cmdShowSource prints the source (AST representation) of all the functions matching a given regex
func cmdSrc(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : print the source code of a function.\n"+
			"\t  src regex prints the AST representation of the function matching the regex\n"+
			"\t  Example:\n", o.EscBlue(), CmdSrcName, o.EscReset())
		o.Write("\t  > %s command-line-arguments.main\n", CmdSrcName)
		return false
	}

	funcs, err := listContextFunc(o, sess, command)
	if err != nil {
		o.WriteErr("%s", err.Error())
		return false
	}
	if len(funcs) == 0 {
		o.WriteErr("Need at least one function to show source for.")
		cmdSrc(o, nil, command, withTest)
	}
	for _, f := range funcs {
		astNode := f.Syntax()
		if astNode == nil {
			o.WriteErr("%s has no syntax.", formatutil.Bold(f.String()))
		} else {
			program, _ := sess.program() // program should be loaded at this point
			if program == nil {
				panic("internal error: program is missing")
			}
			o.WriteSuccess("<<< Source for %s", formatutil.Bold(f.String()))
			printer.Fprint(o.Writer(), program.Fset, astNode)
			o.Write("\n")
			o.WriteSuccess("End of source for %s >>>", f.String())
			o.Write("\n")
		}
	}
	return false
}

// cmdAst prints the AST structure of all the functions matching a given regex
func cmdAst(o Outputter, sess *Session, command Command, withTest bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : print the ast of a function.\n"+
			"\t  %s regex prints the AST structure of the %sfunction%s matching the regex\n"+
			"\t  %s -file regex prints the AST structure of the %sfile%s matching the regex\n"+
			"\t  Example:\n",
			o.EscBlue(), CmdAstName, o.EscReset(),
			CmdAstName, o.EscYellow(), o.EscReset(),
			CmdAstName, o.EscYellow(), o.EscReset())
		o.Write("\t  > %s command-line-arguments.main\n", CmdAstName)
		return false
	}

	if !sess.hasProgram() {
		o.WriteErr("Need a program to show the AST for.")
		o.WriteErr("You should at least loadprogam")
		cmdAst(o, nil, command, withTest)
	}

	// Display the AST of a file?
	if command.Flags["file"] {
		files := findFiles(o, sess, command)
		if len(files) == 0 {
			o.WriteErr("Need at least one file to show the AST for.")
			cmdAst(o, nil, command, withTest)
		} else {
			for _, f := range files {
				filePath := sess.programOrPanic().Fset.Position(f.Pos()).Filename
				if f == nil {
					o.WriteErr("%s has no AST.", formatutil.Bold(filePath))
				} else {
					o.WriteSuccess("<<< AST of %s", formatutil.Bold(filePath))
					ast.Fprint(o.Writer(), sess.programOrPanic().Fset, f, nil)
					printer.Fprint(o.Writer(), sess.programOrPanic().Fset, f)
					o.Write("\n")
					o.WriteSuccess("End of AST of %s >>>", filePath)
					o.Write("\n")
				}
			}
		}
		return false
	}
	// Display the AST of a function
	funcs, err := listContextFunc(o, sess, command)
	if err != nil {
		o.WriteErr("%s", err.Error())
		return false
	}
	if len(funcs) == 0 {
		o.WriteErr("Need at least one function to show the AST for.")
		cmdAst(o, nil, command, withTest)
	}
	for _, f := range funcs {
		astNode := f.Syntax()
		if astNode == nil {
			o.WriteErr("%s has no AST.", formatutil.Bold(f.String()))
		} else {
			o.WriteSuccess("<<< AST of %s", formatutil.Bold(f.String()))
			ast.Fprint(o.Writer(), sess.programOrPanic().Fset, astNode, nil)
			printer.Fprint(o.Writer(), sess.programOrPanic().Fset, astNode)
			o.Write("\n")
			o.WriteSuccess("End of AST of %s >>>", f.String())
			o.Write("\n")
		}
	}
	return false
}

// cmdSummarize runs the intra-procedural analysis.
func cmdSummarize(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s : run the intra-procedural analysis. If a function is provided, "+
			"run only\n", o.EscBlue(), CmdSummarizeName, o.EscReset())
		o.Write("\t   on the provided function\n")
		o.Write("\t   This will build dataflow summaries for all specified functions.\n")
		o.Write("\t   -force flag will force summarization and bypass filters on reachable functions.\n")
		return false
	}

	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	isForced := command.Flags["force"]

	// ensure dataflow state
	res := sess.loadDataflowAnalysis(o)
	if res.IsErr() {
		o.WriteErr("Could not load dataflow: %s", res)
		return false
	}
	c := res.Unwrap()

	if len(command.Args) < 1 {
		// Running the intra-procedural analysis on all functions
		o.WriteSuccess("Running intra-procedural analysis on all functions")
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
		ctx := context.Background()
		dataflow.RunIntraProceduralPass(ctx, c, numRoutines, dataflow.IntraAnalysisParams{
			ShouldBuildSummary: shouldBuildSummary,
			ShouldTrack:        dataflow.IsNodeOfInterest,
		})
		o.WriteSuccess("%d summaries created, %d built", createCounter, buildCounter)
	} else {
		// Running the intra-procedural analysis on a single function, if it can be found
		regex, err := regexp.Compile(command.Args[0])
		if err != nil {
			regexErr(o, command.Args[0], err)
			return false
		}
		funcs, err := sess.findFunc(regex)
		if err != nil {
			o.WriteErr("%s", err.Error())
			return false
		}
		o.WriteSuccess("Running intra-procedural analysis on functions matching %s", command.Args[0])

		// Depending on the summaries threshold and the number of matched functions, different filters are used.
		// If len(funcs) > summarizeThreshold, the filter used is similar to the one used in the taint analysis.
		buildCounter := 0

		var shouldBuildSummary func(c *dataflow.State, f *ssa.Function) bool
		if len(funcs) > summarizeThreshold {
			// above a certain threshold, we use the general analysis filters on what to summarize, unless -force has
			// been specified
			shouldBuildSummary = summarizeWithDefaultParams(o, funcs, isForced, &buildCounter)
		} else {
			// below that threshold, all functions that match are summarize.
			// useful for testing.
			shouldBuildSummary = alwaysSummarize(funcs, &buildCounter)
		}

		// Run the analysis with the filter.
		ctx := context.Background()
		dataflow.RunIntraProceduralPass(ctx, c, numRoutines, dataflow.IntraAnalysisParams{
			ShouldBuildSummary: shouldBuildSummary,
			ShouldTrack:        dataflow.IsNodeOfInterest,
		})
		// Insert the summaries, i.e. only updated the summaries that have been computed and do not discard old ones

		o.WriteSuccess("%d summaries created, %d built.", len(funcs), buildCounter)
		if buildCounter == 0 {
			o.WriteSuccess("The queried functions may not be reachable?")
			o.WriteSuccess("If less than %d functions match the query, then all reachable "+
				"matching functions will be summarized", summarizeThreshold)
		}
	}
	return false
}

func summarizeWithDefaultParams(o Outputter, funcs []*ssa.Function, isForced bool,
	buildCounter *int) func(*dataflow.State, *ssa.Function) bool {
	o.WriteSuccess("(more than %d functions matching, other config-defined filters are in use)",
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
func cmdTaint(o Outputter, sess *Session, _ Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: run the taint analysis with parameters in config.\n",
			o.EscBlue(), CmdTaintName, o.EscReset())
		o.Write("\t   Flow graph must be built first with `%s%s%s`.\n",
			o.EscYellow(), CmdBuildGraphName, o.EscReset())
		return false
	}
	c := sess.loadDataflowAnalysis(o)
	if c.IsErr() {
		o.WriteErr("Failed to load dataflow analysis: %v", c)
		return false
	}
	// load dataflow state
	if !c.Unwrap().FlowGraph.IsBuilt() {
		o.WriteErr("The inter-procedural dataflow graph is not built!")
		o.WriteErr("Please run `%s` before calling `taint`.", CmdBuildGraphName)
		return false
	}
	for _, ts := range c.Unwrap().Config.TaintTrackingProblems {
		ctx := context.Background()
		c.Unwrap().FlowGraph.RunVisitorOnEntryPoints(
			ctx,
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
func cmdBacktrace(o Outputter, sess *Session, _ Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: run the backtrace analysis with parameters in config.\n",
			o.EscBlue(), CmdBacktraceName, o.EscReset())
		o.Write("\t   Flow graph must be built first with `%s%s%s`.\n",
			o.EscYellow(), CmdBuildGraphName, o.EscReset())
		return false
	}

	res := sess.loadDataflowAnalysis(o)
	if res.IsErr() {
		o.WriteErr("Failed to load dataflow analysis: %v", res)
		return false
	}
	c := res.Unwrap()

	if !c.FlowGraph.IsBuilt() {
		o.WriteErr("The inter-procedural dataflow graph is not built!")
		o.WriteErr("Please run `%s` before calling `backtrace`.", CmdBuildGraphName)
		return false
	}

	var traces []backtrace.Trace
	for _, ps := range c.Config.SlicingProblems {
		visitor := backtrace.NewVisitor(ps)
		ctx := context.Background()
		c.FlowGraph.RunVisitorOnEntryPoints(
			ctx,
			visitor,
			dataflow.ScanningSpec{
				IsEntryPointSsa: func(node ssa.Node) (config.CodeIdentifier, bool) {
					return dataflow.IsBacktraceNode(c, &ps, node)
				}})
		for _, tr := range visitor.Traces {
			traces = append(traces, tr...)
		}
	}

	o.Write("Traces:\n")
	for _, trace := range traces {
		o.Write("%v\n", trace)
	}

	return false
}

func printSummary(o Outputter, command Command, summary *dataflow.SummaryGraph) {
	if _, mustFilter := command.NamedArgs["filter"]; mustFilter {
		o.WriteErr("TODO : implement filtering graphs to show only relevant edges.")
	}
	o.WriteSuccess("Found summary of %s:", summary.Parent.String())
	if !summary.Constructed {
		o.Write("  %s(not built)%s\n", o.EscRed(), o.EscReset())
	}
	if summary.IsInterfaceContract {
		o.Write("  (is interface contract)\n")
	}
	o.Write("%s:\n", formatutil.Yellow("Nodes"))
	var regexFilter *regexp.Regexp
	if filter, ok := command.NamedArgs["f"]; ok {
		var err error
		regexFilter, err = regexp.Compile(filter)
		if err != nil {
			regexErr(o, filter, err)
			return
		}
	}
	summary.ForAllNodes(func(n dataflow.GraphNode) {
		if regexFilter != nil && !regexFilter.MatchString(n.String()) {
			return
		}
		o.Write("\t %s\n", n)
	})
	summary.PrettyPrint(true, o.Writer(), regexFilter)
}

func listContextFunc(o Outputter, sess *Session, command Command) ([]*ssa.Function, error) {
	if len(command.Args) < 1 {
		if sess.currentFunction != nil {
			return []*ssa.Function{sess.currentFunction}, nil
		}
		return []*ssa.Function{}, nil
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
		return []*ssa.Function{}, nil
	}

	return sess.findFunc(target)
}

// findFiles finds the ast file in the program loaded.
// You should ensure that the  LPState of the Session has been loaded, otherwise
// this function will just return an empty list.
func findFiles(o Outputter, sess *Session, command Command) []*ast.File {
	if sess.lpState == nil {
		return []*ast.File{}
	}
	if len(command.Args) < 1 {
		o.WriteErr("Need a regex to match files.")
		return []*ast.File{}
	}
	target, err := regexp.Compile(command.Args[0])
	if err != nil {
		regexErr(o, command.Args[0], err)
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
