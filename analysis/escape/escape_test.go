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

package escape

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/analysis/testutils"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"golang.org/x/tools/go/ssa"
)

// Look for a single node by its name prefix. Errors if there is not
// exactly one match
func findSingleNode(t *testing.T, g *EscapeGraph, name string) *Node {
	var node *Node
	for n := range g.edges {
		if strings.HasPrefix(n.debugInfo, name) {
			if node != nil {
				t.Errorf("Duplicate node found for %s\n", name)
				return nil
			} else {
				node = n
			}
		}
	}
	if node == nil {
		t.Errorf("No node found for %s\n", name)
	}
	return node
}

// Ensure there is an edge from a to b
func assertEdge(t *testing.T, g *EscapeGraph, a, b *Node) {
	if succs, ok := g.edges[a]; ok {
		if _, ok := succs[b]; ok {
			return
		}
	}
	t.Errorf("Expected edge between %v -> %v:\n%v\n", a, b, g.Graphviz())
}

// Check the escape results. The expected graph shapes are specific to a single input file, despite the arguments.
//
//gocyclo:ignore
func TestSimpleEscape(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/simple-escape")
	err := os.Chdir(dir)
	if err != nil {
		t.Fatalf("failed to switch to dir %v: %v", dir, err)
	}
	program, _ := analysistest.LoadTest(t, ".", []string{})
	result, _ := dataflow.DoPointerAnalysis(program, func(_ *ssa.Function) bool { return true }, true)

	if len(result.CallGraph.Nodes) < 7 {
		t.Fatalf("Expected at least 7 nodes in the callgraph")
	}
	for _, cgNode := range result.CallGraph.Nodes {
		// Compute the summary of the node
		graph := EscapeSummary(cgNode.Func)
		// A general check to make sure that all global nodes are escaped.
		for n := range graph.edges {
			if strings.HasPrefix(n.debugInfo, "gbl:") && graph.status[n] != Leaked {
				t.Errorf("Global should have escaped %v\n", n)
			}
		}
		// Check properties of each test function.
		switch cgNode.Func.String() {
		case "command-line-arguments.consume":
			x := findSingleNode(t, graph, "gbl:globalS")
			y := findSingleNode(t, graph, "pointee of s")
			assertEdge(t, graph, x, y)
		case "command-line-arguments.leakThroughGlobal":
			x := findSingleNode(t, graph, "gbl:globalS")
			y := findSingleNode(t, graph, "new S")
			assertEdge(t, graph, x, y)
		case "command-line-arguments.testGlobalLoadStore":
			g := findSingleNode(t, graph, "gbl:globalS")
			s := findSingleNode(t, graph, "new S")
			b := findSingleNode(t, graph, "new B")
			l := findSingleNode(t, graph, "*S load")
			r := findSingleNode(t, graph, "return")
			assertEdge(t, graph, g, s)
			assertEdge(t, graph, g, l)
			assertEdge(t, graph, s, b)
			assertEdge(t, graph, r, s)
			assertEdge(t, graph, r, l)
		case "command-line-arguments.testMapValue":
			x := findSingleNode(t, graph, "return")
			y := findSingleNode(t, graph, "new S")
			assertEdge(t, graph, x, y)
		case "command-line-arguments.testMapKey":
			x := findSingleNode(t, graph, "return")
			y := findSingleNode(t, graph, "new S")
			assertEdge(t, graph, x, y)
		case "command-line-arguments.testFieldOfGlobal":
			x := findSingleNode(t, graph, "gbl:GG")
			y := findSingleNode(t, graph, "new B")
			assertEdge(t, graph, x, y)
		case "command-line-arguments.testSlice":
			x := findSingleNode(t, graph, "return")
			if len(graph.edges[x]) == 0 {
				t.Errorf("Slice should return some object")
			}
			for y := range graph.edges[x] {
				if !strings.HasPrefix(y.debugInfo, "new S") {
					t.Errorf("Slice should only return S's")
				}
			}
		}
	}
}

// Looks up a function in the main package
func findFunction(program *ssa.Program, name string) *ssa.Function {
	for _, pkg := range program.AllPackages() {
		if pkg.Pkg.Name() == "main" {
			return pkg.Func(name)
		}
	}
	return nil
}

// Is this instruction a call to a function with this name?
func isCall(instr ssa.Instruction, name string) bool {
	if call, ok := instr.(*ssa.Call); ok && call.Call.StaticCallee() != nil && call.Call.StaticCallee().Name() == name {
		return true
	}
	return false
}

// Re-run the monotone analysis framework to get a result at each function call.
// If the function has the name of one of our special functions, check that its
// arguments meet the required property.
//
//gocyclo:ignore
func checkFunctionCalls(ea *functionAnalysisState, bb *ssa.BasicBlock) error {
	g := NewEmptyEscapeGraph(ea.nodes)
	if len(bb.Preds) == 0 {
		// Entry block uses the function-wide initial graph
		g.Merge(ea.initialGraph)
	} else {
		// Take the union of all our predecessors. Treat nil as no-ops; they will
		// be filled in later, and then the current block will be re-analyzed
		for _, pred := range bb.Preds {
			if predGraph := ea.blockEnd[pred]; predGraph != nil {
				g.Merge(predGraph)
			}
		}
	}
	for _, instr := range bb.Instrs {
		if isCall(instr, "assertSameAliases") {
			args := instr.(*ssa.Call).Call.Args
			if len(args) != 2 {
				return fmt.Errorf("Expected 2 arguments to special assertion")
			}
			a := ea.nodes.ValueNode(args[0])
			b := ea.nodes.ValueNode(args[1])
			//fmt.Printf("Checking call %v %v\n%v\n", a, b, g.Graphviz(ea.nodes))
			if !reflect.DeepEqual(g.edges[a], g.edges[b]) {
				if !(len(g.edges[a]) == 0 && len(g.edges[b]) == 0) {
					// TODO: figure out why deepequal is returning false for two empty maps
					return fmt.Errorf("Arguments do not have the same set of edges %v != %v (%v != %v) %v \n%v", a, b, g.edges[a], g.edges[b], reflect.DeepEqual(g.edges[a], g.edges[b]), g.Graphviz())
				}
			}
		} else if isCall(instr, "assertAllLeaked") {
			args := instr.(*ssa.Call).Call.Args
			if len(args) != 1 {
				return fmt.Errorf("Expected 1 arguments to special assertion")
			}
			a := ea.nodes.ValueNode(args[0])
			for b := range g.edges[a] {
				if g.status[b] != Leaked {
					return fmt.Errorf("%v wasn't leaked in:\n%v", b, g.Graphviz())
				}
			}
		} else if isCall(instr, "assertAllLocal") {
			args := instr.(*ssa.Call).Call.Args
			if len(args) != 1 {
				return fmt.Errorf("Expected 1 arguments to special assertion")
			}
			a := ea.nodes.ValueNode(args[0])
			for b := range g.edges[a] {
				if g.status[b] != Local {
					return fmt.Errorf("%v has escaped in:\n%v", b, g.Graphviz())
				}
			}
		} else {
			ea.transferFunction(instr, g, false)
		}
	}
	return nil
}

// Check the escape results in the interprocedural case
func TestInterproceduralEscape(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/interprocedural-escape")
	err := os.Chdir(dir)
	if err != nil {
		t.Fatalf("failed to switch to dir %v: %v", dir, err)
	}
	program, cfg := analysistest.LoadTest(t, ".", []string{})
	cfg.LogLevel = int(config.TraceLevel)
	// Compute the summaries for everything in the main package
	state, _ := dataflow.NewAnalyzerState(program, config.NewLogGroup(cfg), cfg,
		[]func(*dataflow.AnalyzerState){
			func(s *dataflow.AnalyzerState) { s.PopulatePointersVerbose(summaries.IsUserDefinedFunction) },
		})
	escapeWholeProgram, err := EscapeAnalysis(state, state.PointerAnalysis.CallGraph.Root)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	funcsToTest := []string{
		"testAlias",
		"inverseAlias",
		"inverseLeaked",
		"inverseLocal",
		"inverseLocalEscapedOnly",
		"testTraverseList",
		"testTraverseListRecur",
		"testStepLargeList",
		"testMultiReturnValues",
		"testConsume",
		"testFresh",
		"testIdent",
		"testExternal",
	}
	// For each of these distinguished functions, check that the assert*() functions
	// are satisfied by the computed summaries (technically, the summary at particular
	// program points)
	for _, funcName := range funcsToTest {
		f := findFunction(program, funcName)
		if f == nil {
			t.Fatalf("Could not find function %v\n", funcName)
		}
		summary := escapeWholeProgram.summaries[f]
		if summary == nil {
			t.Fatalf("%v wasn't summarized", funcName)
		}
		for _, bb := range f.Blocks {
			err := checkFunctionCalls(summary, bb)
			// test* == no error, anything else == error expected
			if strings.HasPrefix(funcName, "test") {
				if err != nil {
					t.Fatalf("Error in %v: %v\n", funcName, err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected fail in %v, but no error produced\n", funcName)
				}
			}

		}
	}
}

// Check the escape results in the interprocedural case
func TestBuiltinsEscape(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/builtins-escape")
	err := os.Chdir(dir)
	if err != nil {
		t.Fatalf("failed to switch to dir %v: %v", dir, err)
	}
	program, cfg := analysistest.LoadTest(t, ".", []string{})
	cfg.LogLevel = int(config.DebugLevel)
	// Compute the summaries for everything in the main package
	cache, _ := dataflow.NewInitializedAnalyzerState(config.NewLogGroup(cfg), cfg, program)
	escapeWholeProgram, err := EscapeAnalysis(cache, cache.PointerAnalysis.CallGraph.Root)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	funcsToTest := []string{
		"testMethod",
		"testVarargs",
		"testNilArg",
		"testVariousBuiltins",
		"testGo",
		"testAppend",
		"testIndexArray",
		"testChannel",
		"testChannelEscape",
		"testSelect",
		"testConvertStringToSlice",
	}
	// For each of these distinguished functions, check that the assert*() functions
	// are satisfied by the computed summaries (technically, the summary at particular
	// program points)
	for _, funcName := range funcsToTest {
		f := findFunction(program, funcName)
		if f == nil {
			t.Fatalf("Could not find function %v\n", funcName)
		}
		summary := escapeWholeProgram.summaries[f]
		if summary == nil {
			t.Fatalf("%v wasn't summarized", funcName)
		}
		for _, bb := range f.Blocks {
			err := checkFunctionCalls(summary, bb)
			// test* == no error, anything else == error expected
			if strings.HasPrefix(funcName, "test") {
				if err != nil {
					t.Fatalf("Error in %v: %v\n", funcName, err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected fail in %v, but no error produced\n", funcName)
				}
			}

		}
	}
}

func TestLocalityComputation(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/escape-locality")
	err := os.Chdir(dir)
	if err != nil {
		t.Fatalf("failed to switch to dir %v: %v", dir, err)
	}
	program, cfg := testutils.LoadTest(t, ".", []string{})
	cfg.LogLevel = int(config.DebugLevel)
	// Compute the summaries for everything in the main package
	cache, _ := dataflow.NewInitializedAnalyzerState(config.NewLogGroup(cfg), cfg, program)
	escapeWholeProgram, err := EscapeAnalysis(cache, cache.PointerAnalysis.CallGraph.Root)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	funcsToTest := []string{
		"testLocality",
	}
	// For each of these distinguished functions, check that the assert*() functions
	// are satisfied by the computed summaries (technically, the summary at particular
	// program points)
	for _, funcName := range funcsToTest {
		f := findFunction(program, funcName)
		if f == nil {
			t.Fatalf("Could not find function %v\n", funcName)
		}
		summary := escapeWholeProgram.summaries[f]
		if summary == nil {
			t.Fatalf("%v wasn't summarized", funcName)
		}
		context := ComputeArbitraryCallerGraph(f, escapeWholeProgram)
		locality := ComputeInstructionLocality(f, escapeWholeProgram, context)
		for _, bb := range f.Blocks {
			fmt.Printf("%v\n", bb)
			for _, instr := range bb.Instrs {
				if locality[instr] {
					fmt.Printf("// LOCAL\n")
				} else {
					fmt.Printf("// non-local\n")
				}
				if v, ok := instr.(ssa.Value); ok {
					fmt.Printf("%s = ", v.Name())
				}
				fmt.Printf("%v\n", instr)
			}
		}
	}
}
