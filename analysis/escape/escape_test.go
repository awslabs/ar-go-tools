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
	"embed"
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	resultMonad "github.com/awslabs/ar-go-tools/internal/funcutil/result"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"
)

//go:embed testdata
var testfsys embed.FS

// Look for a single node by its name prefix. Errors if there is not
// exactly one match
func findSingleNode(t *testing.T, g *EscapeGraph, name string) *Node {
	var node *Node
	for n := range g.status {
		if strings.HasPrefix(n.debugInfo, name) {
			if node != nil {
				t.Errorf("Duplicate node found for %s\n", name)
				return nil
			}
			node = n
		}
	}
	if node == nil {
		t.Errorf("No node found for %s\n", name)
	}
	return node
}

// Ensure there is an edge from a to b
func assertEdge(t *testing.T, g *EscapeGraph, a, b *Node) {
	if len(g.Edges(a, b, EdgeAll)) == 0 {
		t.Errorf("Expected edge between %v -> %v:\n%v\n", a, b, g.Graphviz())
	}
}

// unsimplifiedEscapeSummary computes the summary of a function without removing redudant nodes,
// etc., which is required to do some tests that explicitly look for these nodes.
func unsimplifiedEscapeSummary(f *ssa.Function) (graph *EscapeGraph) {
	prog := &ProgramAnalysisState{
		make(map[*ssa.Function]*functionAnalysisState),
		newGlobalNodeGroup(),
		config.NewLogGroup(config.NewDefault()),
		nil,
		false,
	}
	analysis := newFunctionAnalysisState(f, prog, "summarize")
	analysis.Resummarize()
	returnResult := NewEmptyEscapeGraph(analysis.nodes)
	for block, blockEndState := range analysis.blockEnd {
		if len(block.Instrs) > 0 {
			if retInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return); ok {
				returnResult.Merge(blockEndState)
				for i, rValue := range retInstr.Results {
					if IsEscapeTracked(rValue.Type()) {
						returnResult.WeakAssign(analysis.nodes.ReturnNode(i, rValue.Type()), analysis.nodes.ValueNode(rValue))
					}
				}
			}
		}
	}
	return returnResult
}

// Check the escape results. The expected graph shapes are specific to a single input file, despite the arguments.
//
//gocyclo:ignore
func TestSimpleEscape(t *testing.T) {
	t.Parallel()

	dirName := filepath.Join("./testdata", "simple-escape")
	lp, err := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	program := lp.Program
	reachableFunctions := lang.CallGraphReachable(cha.CallGraph(program), false, false)
	result, err := ptr.DoPointerAnalysis(nil, program,
		func(_ *ssa.Function) bool { return true }, reachableFunctions)
	if err != nil {
		t.Fatalf("failed to do pointer analysis: %v", err)
	}
	pkgName := program.AllPackages()[0].Pkg.Path()

	getGraph := func(f string) *EscapeGraph {
		fn := findFunction(program, f)
		cgNode := result.CallGraph.Nodes[fn]
		return unsimplifiedEscapeSummary(cgNode.Func)
	}
	t.Run("consume", func(t *testing.T) {
		graph := getGraph("consume")
		x := findSingleNode(t, graph, "*globalS")
		y := findSingleNode(t, graph, "*s S")
		assertEdge(t, graph, x, y)
	})
	t.Run("leakThroughGlobal", func(t *testing.T) {
		graph := getGraph("leakThroughGlobal")
		x := findSingleNode(t, graph, "*globalS")
		y := findSingleNode(t, graph, "new S")
		assertEdge(t, graph, x, y)
	})
	t.Run("testGlobalLoadStore", func(t *testing.T) {
		graph := getGraph("testGlobalLoadStore")
		g := findSingleNode(t, graph, "*globalS")
		s := findSingleNode(t, graph, "new S")
		b := findSingleNode(t, graph, "new B")
		l := findSingleNode(t, graph, fmt.Sprintf("%v.S load", pkgName))
		r := findSingleNode(t, graph, "return")
		assertEdge(t, graph, g, s)
		assertEdge(t, graph, g, l)
		assertEdge(t, graph, graph.FieldSubnode(s, "Bptr", nil), b)
		assertEdge(t, graph, r, s)
		assertEdge(t, graph, r, l)
	})
	t.Run("testMapValue", func(t *testing.T) {
		graph := getGraph("testMapValue")
		x := findSingleNode(t, graph, "return")
		y := findSingleNode(t, graph, "new S")
		assertEdge(t, graph, x, y)
	})
	t.Run("testMapKey", func(t *testing.T) {
		graph := getGraph("testMapKey")
		x := findSingleNode(t, graph, "return")
		y := findSingleNode(t, graph, "new S")
		assertEdge(t, graph, x, y)
	})
	t.Run("testFieldOfGlobal", func(t *testing.T) {
		graph := getGraph("testFieldOfGlobal")
		x := findSingleNode(t, graph, "*GG")
		y := findSingleNode(t, graph, "new B")
		if x == nil {
			t.Fatalf("x must not be nil")
		}
		x = graph.FieldSubnode(x, "Bptr", nil)
		assertEdge(t, graph, x, y)
	})
	t.Run("testSlice", func(t *testing.T) {
		graph := getGraph("testSlice")
		x := findSingleNode(t, graph, "return")
		if len(graph.Pointees(x)) == 0 {
			t.Errorf("Slice should return some object")
		}
		for y := range graph.Pointees(x) {
			if !strings.HasPrefix(y.debugInfo, "new S") {
				t.Errorf("Slice should only return S's")
			}
		}
	})
	t.Run("testManyAccesses", func(t *testing.T) {
		fn := findFunction(program, "testManyAccesses")
		cgNode := result.CallGraph.Nodes[fn]
		graph := EscapeSummary(cgNode.Func)
		if len(graph.status) > 10 {
			fmt.Printf("Graph is %s", graph.Graphviz())
			t.Errorf("Graph should not be too big")
		}
	})
}

// Looks up a function in the main package
func findFunction(program *ssa.Program, name string) *ssa.Function {
	for _, pkg := range program.AllPackages() {
		if pkg.Pkg.Name() == "main" {
			f := pkg.Func(name)
			if f == nil {
				panic(fmt.Errorf("failed to find function %s", name))
			}
			return f
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
				return fmt.Errorf("expected 2 arguments to special assertion")
			}
			a := ea.nodes.ValueNode(args[0])
			b := ea.nodes.ValueNode(args[1])
			if !reflect.DeepEqual(g.Pointees(a), g.Pointees(b)) {
				if !(len(g.edges[a]) == 0 && len(g.edges[b]) == 0) {
					// TODO: figure out why deepequal is returning false for two empty maps
					return fmt.Errorf("Arguments do not have the same set of edges %v != %v in \n%s", a, b, g.Graphviz())
				}
			}
		} else if isCall(instr, "assertAllLeaked") {
			args := instr.(*ssa.Call).Call.Args
			if len(args) != 1 {
				return fmt.Errorf("expected 1 arguments to special assertion")
			}
			a := ea.nodes.ValueNode(args[0])
			for _, e := range g.Edges(a, nil, EdgeAll) {
				if g.status[e.dest] != Leaked {
					return fmt.Errorf("%v wasn't leaked in:\n%v", e.dest, g.Graphviz())
				}
			}
		} else if isCall(instr, "assertAllLocal") {
			args := instr.(*ssa.Call).Call.Args
			if len(args) != 1 {
				return fmt.Errorf("expected 1 arguments to special assertion")
			}
			a := ea.nodes.ValueNode(args[0])
			for _, e := range g.Edges(a, nil, EdgeAll) {
				if g.status[e.dest] != Local {
					return fmt.Errorf("%v has escaped (because %v) in:\n%v", e.dest, g.rationales[e.dest], g.Graphviz())
				}
			}
		} else if isCall(instr, "assertNotNil") {
			args := instr.(*ssa.Call).Call.Args
			if len(args) != 1 {
				return fmt.Errorf("expected 1 arguments to special assertion")
			}
			a := ea.nodes.ValueNode(args[0])

			if len(g.Edges(a, nil, EdgeAll)) == 0 {
				return fmt.Errorf("%v has no pointees in:\n%s", a, g.Graphviz())
			}
		}
		ea.transferFunction(instr, g, nil)
	}
	return nil
}

// Check the escape results in the interprocedural case
func TestInterproceduralEscape(t *testing.T) {
	t.Parallel()

	dirName := filepath.Join("./testdata", "interprocedural-escape")
	lp, err := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true}).Value()

	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	lp.Config.LogLevel = int(config.ErrLevel)
	// Compute the summaries for everything in the main package
	df, err := resultMonad.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to initialize analyzer state: %v", err)
	}
	escapeWholeProgram, err := EscapeAnalysis(df, df.PointerAnalysis.CallGraph.Root)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	mainFunc := findFunction(lp.Program, "main")
	if mainFunc == nil {
		t.Fatalf("failed to find main function")
	}
	funcsToTest := []string{}
	for _, elem := range df.PointerAnalysis.CallGraph.Nodes[mainFunc].Out {
		funcsToTest = append(funcsToTest, elem.Callee.Func.Name())
	}
	if len(funcsToTest) == 0 {
		t.Fatal("no test functions found")
	}
	// For each of these distinguished functions, check that the assert*() functions
	// are satisfied by the computed summaries (technically, the summary at particular
	// program points)
	for _, funcName := range funcsToTest {
		t.Run(funcName, func(t *testing.T) {
			f := findFunction(lp.Program, funcName)
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
		})
	}
}

// Check the escape results in the interprocedural case
func TestBuiltinsEscape(t *testing.T) {
	t.Parallel()

	dirName := filepath.Join("./testdata", "builtins-escape")
	lp, err := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	lp.Config.LogLevel = int(config.ErrLevel)
	// Compute the summaries for everything in the main package
	cache, _ := resultMonad.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	escapeWholeProgram, err := EscapeAnalysis(cache, cache.PointerAnalysis.CallGraph.Root)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	mainFunc := findFunction(lp.Program, "main")
	funcsToTest := []string{}
	for _, elem := range cache.PointerAnalysis.CallGraph.Nodes[mainFunc].Out {
		funcsToTest = append(funcsToTest, elem.Callee.Func.Name())
	}
	if len(funcsToTest) == 0 {
		t.Fatal("no test functions found")
	}
	// For each of these distinguished functions, check that the assert*() functions
	// are satisfied by the computed summaries (technically, the summary at particular
	// program points)
	for _, funcName := range funcsToTest {
		t.Run(funcName, func(t *testing.T) {
			f := findFunction(lp.Program, funcName)
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
		})
	}
}

// Check the escape results in the standard library case
func TestStdlibEscape(t *testing.T) {
	t.Parallel()

	dirName := filepath.Join("./testdata", "stdlib-escape")
	lp, err := analysistest.LoadTest(testfsys, dirName, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	lp.Config.LogLevel = int(config.ErrLevel)
	// Compute the summaries for everything in the main package
	cache, _ := resultMonad.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	escapeWholeProgram, err := EscapeAnalysis(cache, cache.PointerAnalysis.CallGraph.Root)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	mainFunc := findFunction(lp.Program, "main")
	funcsToTest := []string{}
	for _, elem := range cache.PointerAnalysis.CallGraph.Nodes[mainFunc].Out {
		funcsToTest = append(funcsToTest, elem.Callee.Func.Name())
	}
	if len(funcsToTest) == 0 {
		t.Fatal("no test functions found")
	}
	// For each of these distinguished functions, check that the assert*() functions
	// are satisfied by the computed summaries (technically, the summary at particular
	// program points)
	for _, funcName := range funcsToTest {
		t.Run(funcName, func(t *testing.T) {
			f := findFunction(lp.Program, funcName)
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
		})
	}
}

type callgraphVisitNode struct {
	context  dataflow.EscapeCallContext
	fun      *ssa.Function
	locality map[ssa.Instruction]*dataflow.EscapeRationale
	// we don't explicitly keep track of the children here.
}

func computeNodes(state dataflow.EscapeAnalysisState, root *ssa.Function) []*callgraphVisitNode {
	allNodes := make([]*callgraphVisitNode, 0)
	rootContext := state.ComputeArbitraryContext(root)

	currentNode := map[*ssa.Function]*callgraphVisitNode{}
	var analyze func(f *ssa.Function, ctx dataflow.EscapeCallContext)

	analyze = func(f *ssa.Function, ctx dataflow.EscapeCallContext) {
		var node *callgraphVisitNode
		added := false
		if n, ok := currentNode[f]; !ok {
			// haven't visited this node with the current context
			node = &callgraphVisitNode{ctx, f, make(map[ssa.Instruction]*dataflow.EscapeRationale)}
			currentNode[f] = node
			allNodes = append(allNodes, node)
			added = true
		} else {
			node = n
			changed, merged := node.context.Merge(ctx)
			if !changed {
				// an invocation of analyze further up the stack has already computed locality
				// with a more general context.
				return
			}
			node.context = merged
		}
		locality, callsites := state.ComputeInstructionLocalityAndCallsites(f, node.context)
		node.locality = locality
		for callsite, info := range callsites {
			callees, _ := state.(*escapeAnalysisImpl).state.ResolveCallee(callsite, true)
			for callee := range callees {
				if state.IsSummarized(callee) {
					analyze(callee, info.Resolve(callee))
				}
			}
		}
		if added {
			delete(currentNode, f)
		}
	}
	analyze(root, rootContext)
	return allNodes
}

func groupNodesByFunc(nodes []*callgraphVisitNode) [][]*callgraphVisitNode {
	sets := map[*ssa.Function][]*callgraphVisitNode{}
	for _, n := range nodes {
		sets[n.fun] = append(sets[n.fun], n)
	}
	result := [][]*callgraphVisitNode{}
	for _, ns := range sets {
		result = append(result, ns)
	}
	return result
}

// Checks the annotations for a set of nodes of the same function.
// The annotations on some source line are interpreted as follows:
//   - /// LOCAL
//     All SSA instructions corresponding to this line are local, in all contexts.
//   - /// NONLOCAL
//     At least one corresponding instruction is not local. We need at least one
//     because most source lines become multiple SSA ops, many of which are e.g.
//     purely local FieldAddr computations. Must hold for each context, individually.
//   - /// BOTH
//     In at least one context, acts like LOCAL. In at least one context, acts like
//     NONLOCAL. Because we don't have a way to identify the contexts, this annotation
//     is weaker than it could theoretically be.
func checkLocalityAnnotations(nodes []*callgraphVisitNode, annos map[analysistest.LPos]analysistest.AnnotationID) error {
	if len(nodes) == 0 {
		return nil
	}
	// gather annotations
	f := nodes[0].fun
	// Synthetic functions have no locations, and thus we can't match anything up
	if f.Syntax() == nil {
		return nil
	}
	funcStart := f.Prog.Fset.Position(f.Pos())
	funcEnd := f.Prog.Fset.Position(f.Syntax().End())
	fAnnos := map[int]analysistest.AnnotationID{}
	fAnnosCovered := map[int]map[*callgraphVisitNode]bool{}
	for lpos, kind := range annos {
		if lpos.Filename == funcStart.Filename && funcStart.Line <= lpos.Line && lpos.Line <= funcEnd.Line {
			// Ignore annotations inside closures; those will be caught by the closure itself
			foundClosureContainingAnno := false
			for _, subfunction := range f.AnonFuncs {
				subfuncStart := subfunction.Prog.Fset.Position(f.Pos())
				subfuncEnd := subfunction.Prog.Fset.Position(f.Syntax().End())
				if subfuncStart.Line <= lpos.Line && lpos.Line <= subfuncEnd.Line {
					foundClosureContainingAnno = true
				}
			}
			if !foundClosureContainingAnno {
				fAnnos[lpos.Line] = kind
				fAnnosCovered[lpos.Line] = map[*callgraphVisitNode]bool{}
			}
		}
	}

	for _, node := range nodes {
		for _, bb := range f.Blocks {
			for _, ins := range bb.Instrs {
				if rationale := node.locality[ins]; rationale == nil {
					// ins is local, so do nothing.
				} else {
					pos := f.Prog.Fset.Position(ins.Pos())
					if anno, ok := fAnnos[pos.Line]; ok {
						switch anno.ID {
						case "LOCAL":
							// All instructions for a local line must be local
							return fmt.Errorf("instruction %v on line %v was expected to be local", ins, pos.Line)
						case "NONLOCAL":
							fallthrough
						case "BOTH":
							// In NONLOCAL/BOTH, we don't have enough information to determine if there is an error
							if anno.Meta == "" || strings.Contains(rationale.String(), anno.Meta) {
								fAnnosCovered[pos.Line][node] = true
							} else {
								fmt.Printf("Rationale %s ignored because it doesn't contain %s\n", rationale.String(), anno.Meta)
							}
						}
					}
				}
			}
		}
		// For each context/node, check that NONLOCAL lines are satisfied
		for line, anno := range fAnnos {
			if anno.ID == "NONLOCAL" {
				if !fAnnosCovered[line][node] {
					return fmt.Errorf("line %v was expected to have at least one non-local instruction (with rationale: %s)", line, anno.Meta)
				}
			}
		}
	}

	// Check that BOTH lines are satisfied
	for line, anno := range fAnnos {
		if anno.ID == "BOTH" {
			seenLocal, seenNonlocal := false, false
			for _, n := range nodes {
				if fAnnosCovered[line][n] {
					seenNonlocal = true
				} else {
					seenLocal = true
				}
			}
			if !seenLocal || !seenNonlocal {
				return fmt.Errorf("line %v was expected to be local in some contexts and non-local in others (local: %v, non-local: %v)", line, seenLocal, seenNonlocal)
			}
		}
	}
	return nil
}

func TestLocalityComputation(t *testing.T) {
	t.Parallel()

	// Note: old code to load test from disk instead of embedded file
	// _, filename, _, _ := runtime.Caller(0)
	// dir := path.Join(path.Dir(filename), "testdata/escape-locality")
	// err := os.Chdir(dir)
	// if err != nil {
	// 	t.Fatalf("failed to switch to dir %v: %v", dir, err)
	// }
	// lp, err := analysistest.LoadTestFromDisk(".", []string{})

	dir := filepath.Join("./testdata", "escape-locality")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{ApplyRewrite: true}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	lp.Config.LogLevel = int(config.ErrLevel)
	// Compute the summaries for everything in the main package
	cache, err := resultMonad.Bind(ptr.NewState(lp), dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to initialize analyzer state: %v", err)
	}
	err = InitializeEscapeAnalysisState(cache)
	if err != nil {
		t.Fatalf("Error: %v\n", err)
	}
	escapeWholeProgram := cache.EscapeAnalysisState
	mainFunc := findFunction(lp.Program, "main")
	funcsToTest := []string{}
	for _, elem := range cache.PointerAnalysis.CallGraph.Nodes[mainFunc].Out {
		funcsToTest = append(funcsToTest, elem.Callee.Func.Name())
	}
	if len(funcsToTest) == 0 {
		t.Fatal("no test functions found")
	}

	astFiles := analysistest.AstFiles(lp.Packages)
	annos := annotations(lp.Program.Fset, astFiles)
	for _, funcName := range funcsToTest {
		t.Run(funcName, func(t *testing.T) {
			f := findFunction(lp.Program, funcName)
			if f == nil {
				t.Fatalf("Couldn't find function %v", funcName)
			}
			var anyError error
			allCallgraphWalkNodes := computeNodes(escapeWholeProgram, f)
			for _, nodes := range groupNodesByFunc(allCallgraphWalkNodes) {
				if err := checkLocalityAnnotations(nodes, annos); err != nil {
					anyError = err
				}
			}
			if strings.HasPrefix(funcName, "test") {
				if anyError != nil {
					t.Fatalf("Error %v", anyError)
				}
			} else {
				if anyError == nil {
					t.Fatalf("Expected error, but test passed")
				}
			}
			// Print the end of the function to make logs easier to read
			t.Logf("Completed %v\n", funcName)
		})
	}
}

var localRegex = regexp.MustCompile(`// *(LOCAL) *([^ ].+)?$`)
var nonlocalRegex = regexp.MustCompile(`// *(NONLOCAL) *([^ ].+)?$`)
var bothRegex = regexp.MustCompile(`// *(BOTH) *([^ ].+)?$`)

func annotations(fset *token.FileSet, astFiles []*ast.File) map[analysistest.LPos]analysistest.AnnotationID {
	res := make(map[analysistest.LPos]analysistest.AnnotationID)
	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "// LOCAL"
		a := localRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			rationale := ""
			if len(a) > 2 {
				rationale = a[2]
			}
			relPos := analysistest.NewLPos(pos)
			res[relPos] = analysistest.AnnotationID{
				ID:   "LOCAL",
				Meta: rationale,
				Pos:  relPos,
			}
		}
	})

	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "// NONLOCAL"
		a := nonlocalRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			rationale := ""
			if len(a) > 2 {
				rationale = a[2]
			}
			relPos := analysistest.NewLPos(pos)
			res[relPos] = analysistest.AnnotationID{
				ID:   "NONLOCAL",
				Meta: rationale,
				Pos:  relPos,
			}
		}
	})

	analysistest.MapComments(astFiles, func(c1 *ast.Comment) {
		pos := fset.Position(c1.Pos())
		// Match a "// BOTH"
		a := bothRegex.FindStringSubmatch(c1.Text)
		if len(a) > 1 {
			rationale := ""
			if len(a) > 2 {
				rationale = a[2]
			}
			relPos := analysistest.NewLPos(pos)
			res[relPos] = analysistest.AnnotationID{
				ID:   "BOTH",
				Meta: rationale,
				Pos:  relPos,
			}
		}
	})

	return res
}
