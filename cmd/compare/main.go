// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// render: a tool for rendering various "visualizations" of Go programs.
// -cgout Given a path for a .dot file, generates the callgraph of the program in that file.
// -ssaout Given a path for a folder, generates subfolders with files containing the ssa represention of
//         each package in that file.

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/reachability"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var (
	modeFlag = flag.String("graph", "pointer", "Type of analysis to run. One of: pointer, cha, rta, static, vta")
	binary   = flag.String("binary", "", "Pull the symbol table from specified binary file")
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

var (
	buildmode = ssa.BuilderMode(0)
)

const usage = `Compare the set of reachable functions according to pointer-based analysis, type analysis and 
compiled binary.
Usage:
  compare [options] <package path(s)>
`

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	// The strings constants are used only here
	var callgraphAnalysisMode analysis.CallgraphAnalysisMode
	// modeFlag cannot be null here
	switch *modeFlag {
	case "pointer":
		callgraphAnalysisMode = analysis.PointerAnalysis
	case "cha":
		callgraphAnalysisMode = analysis.ClassHierarchyAnalysis
	case "rta":
		callgraphAnalysisMode = analysis.RapidTypeAnalysis
	case "vta":
		callgraphAnalysisMode = analysis.VariableTypeAnalysis
	case "static":
		callgraphAnalysisMode = analysis.StaticAnalysis
	default:
		_, _ = fmt.Fprintf(os.Stderr, "analysis %s not recognized", *modeFlag)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, analysis.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load program: %v", err)
		return
	}

	var cg *callgraph.Graph

	// Compute the call graph
	fmt.Fprintln(os.Stderr, analysis.Faint("Computing call graph"))
	start := time.Now()
	cg, err = callgraphAnalysisMode.ComputeCallgraph(program)
	cgComputeDuration := time.Since(start).Seconds()
	if err != nil {
		fmt.Fprint(os.Stderr, analysis.Red("Could not compute callgraph: %v\n", err))
		return
	} else {
		fmt.Fprint(os.Stderr, analysis.Faint(fmt.Sprintf("Computed in %.3f s\n", cgComputeDuration)))
	}

	//Load the binary
	var symbols map[string]bool = nil
	if *binary != "" {
		symbols, err = ReadNMFile(*binary)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading binary file", err)
		}
		fmt.Fprintf(os.Stderr, "Read %d text symbols from binary\n", len(symbols))
	}

	callgraph := callgraphReachable(cg, false, false)
	reachable := findReachableNames(program)
	allfuncs := findAllFunctionNames(program)

	stripAllParens(callgraph)
	stripAllParens(reachable)
	stripAllParens(symbols)
	stripAllParens(allfuncs)

	all := make(map[string]bool)

	for f := range callgraph {
		all[f] = true
	}
	for f := range symbols {
		all[f] = true
	}
	for f := range reachable {
		all[f] = true
	}
	for f := range allfuncs {
		all[f] = true
	}

	allsorted := make([]string, 0, len(all))

	for key := range all {
		allsorted = append(allsorted, key)
	}
	sort.Slice(allsorted, func(i, j int) bool {
		return stripLeadingAsterisk(allsorted[i]) < stripLeadingAsterisk(allsorted[j])
	})

	for _, f := range allsorted {
		fmt.Printf("%c %c %c %c %s\n", ch(allfuncs[f]), ch(reachable[f]), ch(callgraph[f]), ch(symbols[f]), f)
	}

	fmt.Printf("%d total functions\n", len(all))
	fmt.Printf("Missing %d from allfuncs, %d from callgraph, %d from reachability, %d from binary\n",
		len(all)-len(allfuncs), len(all)-len(callgraph), len(all)-len(reachable), len(all)-len(symbols))

}

func stripAllParens(m map[string]bool) {
	for key, b := range m {
		if strings.ContainsAny(key, "()") {
			delete(m, key)
			m[stripParens(key)] = b
		}
	}
}

func stripParens(s string) string {
	s1 := strings.ReplaceAll(s, "(", "")
	s2 := strings.ReplaceAll(s1, ")", "")
	return s2
}

func stripLeadingAsterisk(s string) string {
	if len(s) == 0 || s[0] != '*' {
		return s
	}
	return s[1:]
}

func ch(c bool) rune {
	if c {
		return 'X'
	}
	return ' '
}

func callgraphReachable(cg *callgraph.Graph, excludeMain bool, excludeInit bool) map[string]bool {
	fmt.Fprintf(os.Stderr, "callGraph has %d total nodes\n", len(cg.Nodes))

	entryPoints := findCallgraphEntryPoints(cg, excludeMain, excludeInit)
	fmt.Fprintf(os.Stderr, "findCallgraphEntryPoints found %d entry points\n", len(entryPoints))

	//	fmt.Fprintf(os.Stderr, "Root node is %v\n", cg.Root.Func.String())

	reachable := make(map[string]bool, len(cg.Nodes))

	frontier := make([]*callgraph.Node, 0)

	for _, node := range entryPoints {
		//	node := cg.Root
		reachable[node.Func.String()] = true
		frontier = append(frontier, node)
	}

	for len(frontier) != 0 {
		node := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, edge := range node.Out {
			if !reachable[edge.Callee.Func.String()] {
				reachable[edge.Callee.Func.String()] = true
				frontier = append(frontier, edge.Callee)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "Callgraph Reachable reports %d reachable nodes\n", len(reachable))

	return reachable
}

func findCallgraphEntryPoints(cg *callgraph.Graph, excludeMain bool, excludeInit bool) []*callgraph.Node {
	entryPoints := make([]*callgraph.Node, 0)
	for f, node := range cg.Nodes {
		if f == nil {
			fmt.Println("Got a nil function?")
			continue
		}
		var name = f.String()

		if (!excludeMain && name == "command-line-arguments.main") ||
			(!excludeInit && name == "command-line-arguments.init") {
			entryPoints = append(entryPoints, node)
		}
	}
	return entryPoints

}

func funcsToStrings(funcs map[*ssa.Function]bool) map[string]bool {
	names := make(map[string]bool, len(funcs))

	for f, t := range funcs {
		if !t {
			continue
		}
		names[f.String()] = true
	}
	return names
}

func findReachableNames(program *ssa.Program) map[string]bool {
	funcs := reachability.FindReachable(program, false, false, nil)
	return funcsToStrings(funcs)
}

func findAllFunctionNames(program *ssa.Program) map[string]bool {
	funcs := ssautil.AllFunctions(program)
	return funcsToStrings(funcs)
}
