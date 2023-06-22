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
	"bufio"
	"flag"
	"fmt"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/reachability"
	"github.com/awslabs/ar-go-tools/internal/colors"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var (
	modeFlag        = flag.String("analysis", "pointer", "Type of analysis to run. One of: pointer, cha, rta, static, vta")
	compareSymbols  = flag.Bool("symbols", false, "Compare")
	binary          = flag.String("binary", "", "Pull the symbol table from specified binary file")
	dynBinary       = flag.String("dynbinary", "", "Load dynamic callgraph corresponding to the given binary")
	dynCallgraphDir = flag.String("callgraphs", "", "Directory to get dynamic callgraph from")
)

func init() {
	flag.Var(&buildmode, "build", ssa.BuilderModeDoc)
}

var (
	buildmode = ssa.InstantiateGenerics
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
	var callgraphAnalysisMode dataflow.CallgraphAnalysisMode
	// modeFlag cannot be null here
	switch *modeFlag {
	case "pointer":
		callgraphAnalysisMode = dataflow.PointerAnalysis
	case "cha":
		callgraphAnalysisMode = dataflow.ClassHierarchyAnalysis
	case "rta":
		callgraphAnalysisMode = dataflow.RapidTypeAnalysis
	case "vta":
		callgraphAnalysisMode = dataflow.VariableTypeAnalysis
	case "static":
		callgraphAnalysisMode = dataflow.StaticAnalysis
	default:
		_, _ = fmt.Fprintf(os.Stderr, "analysis %s not recognized", *modeFlag)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, colors.Faint("Reading sources")+"\n")

	program, err := analysis.LoadProgram(nil, "", buildmode, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load program: %v", err)
		return
	}

	var cg *callgraph.Graph

	// Compute the call graph
	fmt.Fprintln(os.Stderr, colors.Faint("Computing call graph"))
	start := time.Now()
	cg, err = callgraphAnalysisMode.ComputeCallgraph(program)
	cgComputeDuration := time.Since(start).Seconds()
	if err != nil {
		fmt.Fprint(os.Stderr, colors.Red("Could not compute callgraph: %v\n", err))
		return
	} else {
		fmt.Fprint(os.Stderr, colors.Faint(fmt.Sprintf("Computed in %.3f s\n", cgComputeDuration)))
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

	if *compareSymbols {
		doCompareSymbols(program, cg, symbols)
	}

	if *dynBinary != "" && *dynCallgraphDir != "" {
		callsites := loadDynamicCallgraph(*dynCallgraphDir, *dynBinary)
		reportUncoveredDynamicEdges(program, cg, callsites)
	}
}

func doCompareSymbols(program *ssa.Program, cg *callgraph.Graph, symbols map[string]bool) {
	callgraphReachable := make(map[string]bool)
	for entry := range dataflow.CallGraphReachable(cg, false, false) {
		callgraphReachable[entry.String()] = true
	}
	fmt.Fprintf(os.Stderr, "Callgraph reachability reports %d reachable nodes out of %v total\n",
		len(callgraphReachable), len(cg.Nodes))

	reachable := findReachableNames(program)
	allfuncs := findAllFunctionNames(program)

	stripAllParens(callgraphReachable)
	stripAllParens(reachable)
	stripAllParens(symbols)
	stripAllParens(allfuncs)

	all := make(map[string]bool)

	for f := range callgraphReachable {
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
		fmt.Printf("%c %c %c %c %s\n", ch(allfuncs[f], 'A'), ch(reachable[f], 'r'), ch(callgraphReachable[f], 'c'),
			ch(symbols[f], 's'), f)
	}
	fmt.Printf("%d total functions\n", len(all))
	fmt.Printf("Missing %d from allfuncs, %d from callgraph, %d from reachability, %d from binary\n",
		len(all)-len(allfuncs), len(all)-len(callgraphReachable), len(all)-len(reachable), len(all)-len(symbols))
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

func ch(c bool, char rune) rune {
	if c {
		return char
	}
	return ' '
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

type dynamicEdge struct {
	callerFile string
	callerLine int
	calleeFile string
	calleeLine int
}

func loadDynamicCallgraph(folder string, binaryName string) map[dynamicEdge]bool {
	files, err := os.ReadDir(folder)
	if err != nil {
		return nil
	}
	dynamicEdges := map[dynamicEdge]bool{}
	for _, fileInfo := range files {
		if m, _ := regexp.MatchString("callgraph-"+regexp.QuoteMeta(binaryName)+"-[0-9]+.out", fileInfo.Name()); m {
			loadCalledges(dynamicEdges, filepath.Join(folder, fileInfo.Name()))
		}
	}
	fmt.Printf("Found total of %v dynamic edges\n", len(dynamicEdges))
	return dynamicEdges
}

// Normalizes the paths that occur on dev-desktops, due to the symlink between /home and /local/home.
// Some parts of the go system resolve this symlink and others don't, and we want to be certain that
// we compare paths accurately.
func normalizeDynamicEdge(de dynamicEdge) dynamicEdge {
	if strings.HasPrefix(de.callerFile, "/local/home/") {
		de.callerFile = de.callerFile[6:]
	}
	if strings.HasPrefix(de.calleeFile, "/local/home/") {
		de.calleeFile = de.calleeFile[6:]
	}
	return de
}

func loadCalledges(edges map[dynamicEdge]bool, file string) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("Error opening: %v\n", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	r := regexp.MustCompile("^(.+):([0-9]+) -> (.+):([0-9]+)\\w*$")
	for scanner.Scan() {
		if parts := r.FindStringSubmatch(scanner.Text()); len(parts) > 0 {
			a, err := strconv.Atoi(parts[2])
			if err != nil {
				continue
			}
			b, err := strconv.Atoi(parts[4])
			if err != nil {
				continue
			}
			edges[normalizeDynamicEdge(dynamicEdge{parts[1], a, parts[3], b})] = true
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

// This adds edges that are reachable from static callees of a function, but for which
// the pointer analysis may not have callsite entries. This ensures these edges are not
// false positives.
func visitStaticReachableEdges(program *ssa.Program, root *ssa.Function, remainingCalledges map[dynamicEdge]bool) {
	visited := map[*ssa.Function]bool{root: true}
	worklist := []*ssa.Function{root}
	for len(worklist) > 0 {
		fun := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		for _, bb := range fun.Blocks {
			for _, ins := range bb.Instrs {
				switch in := ins.(type) {
				case *ssa.Call:
					callerPosition := program.Fset.Position(ins.Pos())
					if _, ok := in.Call.Value.(*ssa.Builtin); !ok {
						if callee := in.Call.StaticCallee(); callee != nil {
							if _, ok := visited[callee]; !ok {
								worklist = append(worklist, callee)
								visited[callee] = true
							}
							calleePosition := program.Fset.Position(callee.Pos())
							edge := dynamicEdge{callerPosition.Filename, callerPosition.Line,
								calleePosition.Filename, calleePosition.Line}
							edge = normalizeDynamicEdge(edge)
							delete(remainingCalledges, edge)
						}
					}
				}
			}
		}
	}
}

// This function analyzes the static callgraph and prints a report about the dynamic
// edges that are NOT present in the static callgraph. These edges are potential points
// of unsoundness. They may not represent actual unsoundness for a few reasons:
// - inlining, where the dynamic edge will cross multiple levels of the static graph
// - runtime functions, where the actual stack has extra calls used to implement go level semantics
// - certain autogenerated functions, that can't be lined up by file:line positions
// - implementations of runtime functions that are treated specially by the pointer analysis
// - low level calls inserted directly by the runtime (e.g. godebug related and init functions)
//
// Some attempt to filter common classes of these false positives has been made (see below).
// Additionally, due to the file:line level matching, some false negatives may occur, i.e.
// edges in the dynamic but not static graph may not be reported.
//
//gocyclo:ignore
func reportUncoveredDynamicEdges(program *ssa.Program, static *callgraph.Graph, dyn map[dynamicEdge]bool) {
	reachable := dataflow.CallGraphReachable(static, false, false)
	remainingCalledges := make(map[dynamicEdge]bool)
	for k, v := range dyn {
		remainingCalledges[k] = v
	}

	for fun, node := range static.Nodes {
		if fun == nil {
			continue
		}
		if _, ok := reachable[fun]; !ok {
			continue
		}
		deferResults := defers.AnalyzeFunction(fun, config.NewLogGroup(config.NewDefault()))
		for _, bb := range fun.Blocks {
			for insIndex, ins := range bb.Instrs {
				switch in := ins.(type) {
				case *ssa.Call:
					callerPosition := program.Fset.Position(ins.Pos())
					if _, ok := in.Call.Value.(*ssa.Builtin); !ok {
						for _, edge := range node.Out {
							if edge.Site == ins {
								c := edge.Callee.Func
								calleePosition := program.Fset.Position(c.Pos())
								edge := dynamicEdge{callerPosition.Filename, callerPosition.Line,
									calleePosition.Filename, calleePosition.Line}
								edge = normalizeDynamicEdge(edge)
								delete(remainingCalledges, edge)
							}
						}
						// Functions that are treated specially by the pointer analysis
						// do not have their bodies analyzed, and so even static callsites
						// are not in the callgraph.Graph. This explicitly covers those
						// callsites and removes them from remainingCalledges
						if callee := in.Call.StaticCallee(); callee != nil {
							if _, ok := reachable[callee]; !ok {
								visitStaticReachableEdges(program, callee, remainingCalledges)
							}
							calleePosition := program.Fset.Position(callee.Pos())
							edge := dynamicEdge{callerPosition.Filename, callerPosition.Line, calleePosition.Filename,
								calleePosition.Line}
							delete(remainingCalledges, edge)
						}
					}
				case *ssa.RunDefers:
					callerPosition := program.Fset.Position(findRunDefersSourcePosition(in, insIndex))
					possibleDefers := deferResults.RunDeferSets[in]
					for _, d := range possibleDefers {
						for _, entry := range d {
							defInstr := fun.Blocks[entry.Block].Instrs[entry.Ins].(*ssa.Defer)
							for _, edge := range node.Out {
								if edge.Site == defInstr {
									c := edge.Callee.Func
									calleePosition := program.Fset.Position(c.Pos())
									edge := dynamicEdge{callerPosition.Filename, callerPosition.Line,
										calleePosition.Filename, calleePosition.Line}
									edge = normalizeDynamicEdge(edge)
									delete(remainingCalledges, edge)
								}
							}
						}
					}
				}
			}
		}
	}
	erasedFromProc, erasedFromAsm, erasedFromMapHasher := 0, 0, 0
	for edge := range remainingCalledges {
		// Init calls and the jump into main come from /src/runtime/proc.go
		if strings.HasSuffix(edge.callerFile, "/src/runtime/proc.go") {
			delete(remainingCalledges, edge)
			erasedFromProc += 1
		}
		// goroutines have a parent in asm_{GOARCH}.s. Only do amd64 for now
		if strings.HasSuffix(edge.callerFile, "/src/runtime/asm_amd64.s") {
			delete(remainingCalledges, edge)
			erasedFromAsm += 1
		}
		// These are most likely calls to hasher(), which gets generated by
		// the compiler directly, and has no source location.
		if strings.HasSuffix(edge.callerFile, "/src/runtime/map.go") &&
			strings.HasPrefix(edge.calleeFile, "<autogenerated>") {
			delete(remainingCalledges, edge)
			erasedFromMapHasher += 1
		}

	}
	fmt.Printf("Removed %v edges for init functions\n", erasedFromProc)
	fmt.Printf("Removed %v edges for goroutines\n", erasedFromAsm)
	fmt.Printf("Removed %v edges for map hasher\n", erasedFromMapHasher)
	fmt.Printf("Remaining dynamic edges: %v of %v\n", len(remainingCalledges), len(dyn))

	sortRemaining := make([]dynamicEdge, 0, len(remainingCalledges))
	for edge := range remainingCalledges {
		sortRemaining = append(sortRemaining, edge)
	}
	sort.Slice(sortRemaining, func(i, j int) bool {
		if sortRemaining[i].callerFile < sortRemaining[j].callerFile {
			return true
		}
		if sortRemaining[i].callerFile > sortRemaining[j].callerFile {
			return false
		}
		if sortRemaining[i].callerLine < sortRemaining[j].callerLine {
			return true
		}
		if sortRemaining[i].callerLine > sortRemaining[j].callerLine {
			return false
		}
		if sortRemaining[i].calleeFile < sortRemaining[j].calleeFile {
			return true
		}
		if sortRemaining[i].calleeFile > sortRemaining[j].calleeFile {
			return false
		}
		if sortRemaining[i].calleeLine < sortRemaining[j].calleeLine {
			return true
		}
		if sortRemaining[i].calleeLine > sortRemaining[j].calleeLine {
			return false
		}
		return false
	})
	for _, edge := range sortRemaining {
		fmt.Printf("  %v:%v -> %v:%v\n", edge.callerFile, edge.callerLine, edge.calleeFile, edge.calleeLine)
	}
	if len(sortRemaining) == 0 {
		fmt.Printf("<no dynamic edges not covered by a static edge>\n")
	}
}

// This is a hack to find the source location for a RunDefers. We take the source position of the next
// instruction, if it is given. This should usually be a return instruction. Sometimes, the return
// instruction has no location, when it is implicit. We use the position of the end of the function in
// this case. Note that as observed in the documentation for rundefers, it isn't always before a return.
// In that case we might return something spurious.
func findRunDefersSourcePosition(ins *ssa.RunDefers, index int) token.Pos {
	blk := ins.Block()
	for index < len(blk.Instrs) {
		if p := blk.Instrs[index].Pos(); p != 0 {
			return p
		}
		if _, ok := blk.Instrs[index].(*ssa.Return); ok {
			return ins.Parent().Syntax().End()
		}
		index += 1
	}
	return 0
}
