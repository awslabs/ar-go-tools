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

package lang_test

import (
	"embed"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	cg "golang.org/x/tools/go/callgraph"
)

//go:embed testdata
var testfsys embed.FS

func TestPointerCallgraph(t *testing.T) {
	dir := filepath.Join("testdata", "callgraph")
	lp, err := analysistest.LoadTest(testfsys, dir, []string{}, analysistest.LoadTestOptions{ApplyRewrite: false}).Value()
	if err != nil {
		t.Fatalf("failed to load test: %v", err)
	}
	program := lp.Program
	callgraph, err := lang.PointerAnalysis.ComputeCallgraph(program)
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
