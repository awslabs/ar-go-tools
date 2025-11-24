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

package lang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// pathSensitiveInstrOpTemplate implements a simple instruction counter.
// Additionally, it prints the current count each time it encounters a return statement.
type InstructionCountingOp struct {
	report    bool
	pass      *analysis.Pass
	lastBlock *ssa.BasicBlock
	count     int
}

func (v *InstructionCountingOp) DoDebugRef(context.Context, *ssa.DebugRef)               { v.count++ }
func (v *InstructionCountingOp) DoUnOp(context.Context, *ssa.UnOp)                       { v.count++ }
func (v *InstructionCountingOp) DoBinOp(context.Context, *ssa.BinOp)                     { v.count++ }
func (v *InstructionCountingOp) DoCall(context.Context, *ssa.Call)                       { v.count++ }
func (v *InstructionCountingOp) DoChangeInterface(context.Context, *ssa.ChangeInterface) { v.count++ }
func (v *InstructionCountingOp) DoChangeType(context.Context, *ssa.ChangeType)           { v.count++ }
func (v *InstructionCountingOp) DoConvert(context.Context, *ssa.Convert)                 { v.count++ }
func (v *InstructionCountingOp) DoSliceArrayToPointer(context.Context, *ssa.SliceToArrayPointer) {
	v.count++
}
func (v *InstructionCountingOp) DoMakeInterface(context.Context, *ssa.MakeInterface) { v.count++ }
func (v *InstructionCountingOp) DoExtract(context.Context, *ssa.Extract)             { v.count++ }
func (v *InstructionCountingOp) DoSlice(context.Context, *ssa.Slice)                 { v.count++ }

// Only the DoReturn reports something in the pass.
func (v *InstructionCountingOp) DoReturn(_ context.Context, ret *ssa.Return) {
	if v.report && ret.Pos() != 0 {
		v.pass.Reportf(ret.Pos(), "count %d instructions at return", v.count)
	}
	v.count++
}

func (v *InstructionCountingOp) DoRunDefers(context.Context, *ssa.RunDefers)     { v.count++ }
func (v *InstructionCountingOp) DoPanic(context.Context, *ssa.Panic)             { v.count++ }
func (v *InstructionCountingOp) DoSend(context.Context, *ssa.Send)               { v.count++ }
func (v *InstructionCountingOp) DoStore(context.Context, *ssa.Store)             { v.count++ }
func (v *InstructionCountingOp) DoIf(context.Context, *ssa.If)                   { v.count++ }
func (v *InstructionCountingOp) DoJump(context.Context, *ssa.Jump)               { v.count++ }
func (v *InstructionCountingOp) DoDefer(context.Context, *ssa.Defer)             { v.count++ }
func (v *InstructionCountingOp) DoGo(context.Context, *ssa.Go)                   { v.count++ }
func (v *InstructionCountingOp) DoMakeChan(context.Context, *ssa.MakeChan)       { v.count++ }
func (v *InstructionCountingOp) DoAlloc(context.Context, *ssa.Alloc)             { v.count++ }
func (v *InstructionCountingOp) DoMakeSlice(context.Context, *ssa.MakeSlice)     { v.count++ }
func (v *InstructionCountingOp) DoMakeMap(context.Context, *ssa.MakeMap)         { v.count++ }
func (v *InstructionCountingOp) DoRange(context.Context, *ssa.Range)             { v.count++ }
func (v *InstructionCountingOp) DoNext(context.Context, *ssa.Next)               { v.count++ }
func (v *InstructionCountingOp) DoFieldAddr(context.Context, *ssa.FieldAddr)     { v.count++ }
func (v *InstructionCountingOp) DoField(context.Context, *ssa.Field)             { v.count++ }
func (v *InstructionCountingOp) DoIndexAddr(context.Context, *ssa.IndexAddr)     { v.count++ }
func (v *InstructionCountingOp) DoIndex(context.Context, *ssa.Index)             { v.count++ }
func (v *InstructionCountingOp) DoLookup(context.Context, *ssa.Lookup)           { v.count++ }
func (v *InstructionCountingOp) DoMapUpdate(context.Context, *ssa.MapUpdate)     { v.count++ }
func (v *InstructionCountingOp) DoTypeAssert(context.Context, *ssa.TypeAssert)   { v.count++ }
func (v *InstructionCountingOp) DoMakeClosure(context.Context, *ssa.MakeClosure) { v.count++ }
func (v *InstructionCountingOp) DoPhi(context.Context, *ssa.Phi)                 { v.count++ }
func (v *InstructionCountingOp) DoSelect(context.Context, *ssa.Select)           { v.count++ }

// Implement path sensitivity operations
func (v *InstructionCountingOp) NewPath() {
	fmt.Printf("Path:")
}

func (v *InstructionCountingOp) EndPath() {
	fmt.Printf(".\n")
	// Last Block of path should have a return
	if v.lastBlock != nil && !LastInstrIsReturn(v.lastBlock) {
		panic(v)
	}
}

func (v *InstructionCountingOp) NewBlock(block *ssa.BasicBlock) {
	fmt.Printf("%d-", block.Index)
	v.lastBlock = block
}

// For testing purposes only: an analyzer that identifies where sources are
// Wrap the source identification into an analysis pass for testing purposes
var taintSourcesAnalyzer = &analysis.Analyzer{
	Name:     "visitor_test",
	Doc:      "Runs a simple visitor for testing.",
	Run:      runVisitorPass,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

func runVisitorPass(pass *analysis.Pass) (interface{}, error) {

	ssaInfo := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	for _, function := range ssaInfo.SrcFuncs {
		fmt.Printf("Function: %q\n", formatutil.Sanitize(function.Name()))
		op := &InstructionCountingOp{pass: pass, count: 0, report: true}
		RunDFS(context.Background(), op, function)
		// Don't report on second run
		op.report = false
		RunAllPaths(context.Background(), op, function)
	}
	return nil, nil
}

func TestAll(t *testing.T) {
	var err error
	// TaintFlows
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %s", err)
	}
	testdata := filepath.Join(wd, "testdata")

	analysistest.Run(t, testdata, taintSourcesAnalyzer, "ssavisitor")
}
