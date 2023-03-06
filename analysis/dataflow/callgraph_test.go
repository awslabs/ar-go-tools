package dataflow_test

import (
	"path"
	"runtime"
	"testing"

	df "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/utils"
	cg "golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func methodTest(t *testing.T, impl map[string]map[*ssa.Function]bool, name string, expect map[string]bool) {
	implementsName := impl[name]
	if implementsName == nil {
		t.Fatalf("interface method %s undefined", name)
	} else if len(implementsName) != len(expect) {
		for f := range implementsName {
			t.Logf("Implements: %s", f.String())
		}
		t.Fatalf("method %s has %d implementations, not %d", name, len(implementsName), len(expect))
	} else {
		for f := range implementsName {
			if f == nil {
				t.Fatalf("method %s has a nil implementations", name)
			}
			if !expect[f.String()] {
				t.Fatalf("method %s has an unexpected implementation %s", name, f.String())
			}
		}
	}
}

func TestPointerCallgraph(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/dataflow")
	program, _ := utils.LoadTest(t, dir, []string{})
	callgraph, err := df.PointerAnalysis.ComputeCallgraph(program)
	if err != nil {
		t.Fatalf("error computing callgraph: %s", err)
	}
	root := callgraph.Root
	if root == nil {
		t.Fatalf("error computing callgraph: root is nil")
	}
	if root.Func.Name() != "<root>" {
		t.Fatalf("root in pointer callgraph should be virtual <root>")
	}
	// <root> -> main
	var cur *cg.Node
	for _, edge := range root.Out {
		if edge.Callee.Func.Name() == "main" {
			cur = edge.Callee
		}
	}
	if cur == nil {
		t.Fatalf("did not find main in callgraph")
	}
	// main -> callInterfaceJMethod x 2
	countCall := 0
	for _, edge := range cur.Out {
		t.Logf("main -> %s", edge.Callee.Func.Name())
		if edge.Callee.Func.Name() == "callInterfaceIMethod" {
			cur = edge.Callee
			countCall++
		}
	}
	if countCall != 2 {
		t.Fatalf("main should call callInterfaceIMethod twice")
	}
	var callF []*cg.Node
	for _, edge := range cur.Out {
		t.Logf("callInterfaceIMethod -> %s", edge.Callee.Func.Name())
		if edge.Callee.Func.Name() == "f" {
			callF = append(callF, edge.Callee)
		}
	}
	if len(callF) != 2 {
		t.Logf("callInterfaceIMethod should have to calls to f for each possible interface")
	}
	for _, cur := range callF {
		for _, edge := range cur.Out {
			t.Logf("%s -> %s", cur.Func.String(), edge.Callee.Func.Name())
		}
	}
}
