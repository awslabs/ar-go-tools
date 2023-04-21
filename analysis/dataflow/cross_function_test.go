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

package dataflow_test

import (
	"fmt"
	"log"
	"path"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/summaries"
	"github.com/awslabs/argot/analysis/taint"
	"github.com/awslabs/argot/analysis/utils"
	"golang.org/x/tools/go/ssa"
)

func TestCrossFunctionFlowGraph(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/dataflow/summaries")
	// Loading the program for testdata/src/dataflow/sumaries/main.go
	program, _ := utils.LoadTest(t, dir, []string{})

	cache, err := dataflow.BuildFullCache(log.Default(), config.NewDefault(), program)
	if err != nil {
		t.Fatalf("failed to build program cache: %v", err)
	}
	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	// Only build summaries for non-stdlib functions here
	shouldCreateSummary := func(f *ssa.Function) bool {
		return !summaries.IsStdFunction(f) && summaries.IsUserDefinedFunction(f)
	}

	analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
		Cache:               cache,
		NumRoutines:         numRoutines,
		ShouldCreateSummary: shouldCreateSummary,
		ShouldBuildSummary:  taint.ShouldBuildSummary,
		IsEntrypoint:        func(*config.Config, ssa.Node) bool { return true },
	})

	cache, err = analysis.BuildCrossFunctionGraph(cache)
	if err != nil {
		t.Fatalf("failed to build cross-function graph: %v", err)
	}

	graph := cache.FlowGraph

	// test duplicate edges
	seenForward := map[string]bool{}
	if len(graph.ForwardEdges) < 2 {
		t.Errorf("graph should have forward edges: %v", graph.ForwardEdges)
	}
	for src := range graph.ForwardEdges {
		if _, ok := seenForward[src.String()]; ok {
			t.Errorf("duplicate src forward edge: %v", src)
		}
		seenForward[src.String()] = true
	}

	if len(graph.BackwardEdges) < 2 {
		t.Errorf("graph should have backward edges: %v", graph.BackwardEdges)
	}
	seenBackward := map[string]bool{}
	for src := range graph.BackwardEdges {
		if _, ok := seenBackward[src.String()]; ok {
			t.Errorf("duplicate src backward edge: %v", src)
		}
		seenBackward[src.String()] = true
	}

	if numEdges(graph.ForwardEdges) != numEdges(graph.BackwardEdges) {
		t.Errorf("graph # forward edges != # backward edges:\n")
		logEdges(t, graph)
	}

	// test globals
	if len(graph.Globals) == 0 {
		t.Error("graph should have globals")
	}
	hasWrite := false
	hasRead := false
	for _, accesses := range graph.Globals {
		for access := range accesses {
			if access.IsWrite {
				hasWrite = true
			} else {
				hasRead = true
			}
		}
	}
	if !hasWrite {
		t.Error("graph should have access global node write")
	}
	if !hasRead {
		t.Error("graph should have access global node read")
	}

	// test forward edges
	for src, dsts := range graph.ForwardEdges {
		switch src.(type) {
		case *dataflow.ParamNode, *dataflow.CallNode, *dataflow.ClosureNode:
			t.Errorf("node should not be the src of a forward edge: %v", src)
		case *dataflow.CallNodeArg:
			if len(dsts) == 0 {
				t.Errorf("expected call node arg forward src to have dsts: %v", src)
			}
			for dst := range dsts {
				if _, ok := dst.(*dataflow.ParamNode); !ok {
					t.Errorf("expected call node arg forward edge dst to be param, got: %v -> %v", src, dst)
				}
			}
		case *dataflow.ReturnNode:
			if len(dsts) == 0 {
				t.Errorf("expected return node forward src to have dsts: %v", src)
			}
			for dst := range dsts {
				_, isCall := dst.(*dataflow.CallNode)
				_, isClosure := dst.(*dataflow.ClosureNode)
				if !(isCall || isClosure) {
					t.Errorf("expected return node forward edge dst to be call or closure, got: %v -> %v", src, dst)
				}
			}
		default:
			t.Errorf("unhandled node type: %T", src)
		}

		for dst := range dsts {
			if _, ok := graph.BackwardEdges[dst]; !ok {
				t.Errorf("graph should have a backward edge starting at %v corresponding to forward edge origin %v", dst, src)
			}
		}
	}

	// test backward edges
	for src, dsts := range graph.BackwardEdges {
		switch src.(type) {
		case *dataflow.CallNodeArg, *dataflow.ReturnNode:
			t.Errorf("node should not be the src of a backward edge: %v", src)
		case *dataflow.ParamNode:
			if len(dsts) == 0 {
				t.Errorf("expected param node backward src to have dsts: %v", src)
			}
			for dst := range dsts {
				if _, ok := dst.(*dataflow.CallNodeArg); !ok {
					t.Errorf("expected param node backward edge dst to be call node arg, got: %v -> %v", src, dst)
				}
			}
		case *dataflow.CallNode:
			if len(dsts) == 0 {
				t.Errorf("expected call node backward src to have dsts: %v", src)
			}
			for dst := range dsts {
				if _, ok := dst.(*dataflow.ReturnNode); !ok {
					t.Errorf("expected call node backward edge dst to be return node, got: %v -> %v", src, dst)
				}
			}
		case *dataflow.ClosureNode:
			if len(dsts) == 0 {
				t.Errorf("expected closure node backward src to have dsts: %v", src)
			}
			for dst := range dsts {
				if _, ok := dst.(*dataflow.ReturnNode); !ok {
					t.Errorf("expected closure node backward edge dst to be return node, got: %v -> %v", src, dst)
				}
			}
		default:
			t.Errorf("unhandled node type: %T", src)
		}

		for dst := range dsts {
			if _, ok := graph.ForwardEdges[dst]; !ok {
				t.Errorf("graph should have a forward edge starting at %v corresponding to backward edge origin %v", dst, src)
			}
		}
	}
}

// numEdges returns the number of dst nodes in edges. This is used for debugging.
func numEdges(edges map[dataflow.GraphNode]map[dataflow.GraphNode]bool) int {
	num := 0
	for _, dsts := range edges {
		num += len(dsts)
	}

	return num
}

// logEdges logs the forward and backward edges (where edge is src -> dst) of graph in alphabetical order:
// - forward edges are sorted by the order of src
// - backward edges are sorted by the order of dst
//
// This is used for debugging.
func logEdges(t *testing.T, graph *dataflow.CrossFunctionFlowGraph) {
	sortedForward := make([]string, 0, len(graph.ForwardEdges))
	for src, dsts := range graph.ForwardEdges {
		for dst := range dsts {
			sortedForward = append(sortedForward, fmt.Sprintf("%s -> %s", src, dst))
		}
	}
	sort.Slice(sortedForward, func(i, j int) bool { return sortedForward[i] < sortedForward[j] })

	sortedBackward := make([]string, 0, len(graph.BackwardEdges))
	for src, dsts := range graph.BackwardEdges {
		for dst := range dsts {
			sortedBackward = append(sortedBackward, fmt.Sprintf("%s -> %s", src, dst))
		}
	}
	sort.Slice(sortedBackward, func(i, j int) bool {
		dstI := strings.TrimSpace(strings.Split(sortedBackward[i], "->")[1])
		dstJ := strings.TrimSpace(strings.Split(sortedBackward[j], "->")[1])
		return dstI < dstJ
	})

	t.Log("FORWARD:")
	for _, f := range sortedForward {
		t.Logf("\t%s\n", f)
	}
	t.Log("BACKWARD:")
	for _, f := range sortedBackward {
		t.Logf("\t%s\n", f)
	}
}