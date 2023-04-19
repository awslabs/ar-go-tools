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
	"os"
	"path"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/utils"
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
	t.Errorf("Expected edge between %v -> %v\n", a, b)
}

// Check the escape results. The expected graph shapes are specific to a single input file, despite the arguments.
func TestSimpleEscape(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/simple-escape")
	err := os.Chdir(dir)
	if err != nil {
		t.Fatalf("failed to switch to dir %v: %v", dir, err)
	}
	program, _ := utils.LoadTest(t, ".", []string{})
	result, err := dataflow.DoPointerAnalysis(program, func(_ *ssa.Function) bool { return true }, true)

	if len(result.CallGraph.Nodes) < 7 {
		t.Fatalf("Expected at least 7 nodes in the callgraph")
	}
	for _, cgNode := range result.CallGraph.Nodes {
		// Compute the summary of the node
		_, graph := EscapeSummary(cgNode.Func)
		// A general check to make sure that all global nodes are escaped.
		for n := range graph.edges {
			if strings.HasPrefix(n.debugInfo, "gbl:") && !graph.escaped[n] {
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
			l := findSingleNode(t, graph, "S load")
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
