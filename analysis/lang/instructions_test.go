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

func (v *InstructionCountingOp) DoDebugRef(*ssa.DebugRef)                       { v.count++ }
func (v *InstructionCountingOp) DoUnOp(*ssa.UnOp)                               { v.count++ }
func (v *InstructionCountingOp) DoBinOp(*ssa.BinOp)                             { v.count++ }
func (v *InstructionCountingOp) DoCall(*ssa.Call)                               { v.count++ }
func (v *InstructionCountingOp) DoChangeInterface(*ssa.ChangeInterface)         { v.count++ }
func (v *InstructionCountingOp) DoChangeType(*ssa.ChangeType)                   { v.count++ }
func (v *InstructionCountingOp) DoConvert(*ssa.Convert)                         { v.count++ }
func (v *InstructionCountingOp) DoSliceArrayToPointer(*ssa.SliceToArrayPointer) { v.count++ }
func (v *InstructionCountingOp) DoMakeInterface(*ssa.MakeInterface)             { v.count++ }
func (v *InstructionCountingOp) DoExtract(*ssa.Extract)                         { v.count++ }
func (v *InstructionCountingOp) DoSlice(*ssa.Slice)                             { v.count++ }

// Only the DoReturn reports something in the pass.
func (v *InstructionCountingOp) DoReturn(ret *ssa.Return) {
	if v.report && ret.Pos() != 0 {
		v.pass.Reportf(ret.Pos(), fmt.Sprintf("count %d instructions at return", v.count))
	}
	v.count++
}

func (v *InstructionCountingOp) DoRunDefers(*ssa.RunDefers)     { v.count++ }
func (v *InstructionCountingOp) DoPanic(*ssa.Panic)             { v.count++ }
func (v *InstructionCountingOp) DoSend(*ssa.Send)               { v.count++ }
func (v *InstructionCountingOp) DoStore(*ssa.Store)             { v.count++ }
func (v *InstructionCountingOp) DoIf(*ssa.If)                   { v.count++ }
func (v *InstructionCountingOp) DoJump(*ssa.Jump)               { v.count++ }
func (v *InstructionCountingOp) DoDefer(*ssa.Defer)             { v.count++ }
func (v *InstructionCountingOp) DoGo(*ssa.Go)                   { v.count++ }
func (v *InstructionCountingOp) DoMakeChan(*ssa.MakeChan)       { v.count++ }
func (v *InstructionCountingOp) DoAlloc(*ssa.Alloc)             { v.count++ }
func (v *InstructionCountingOp) DoMakeSlice(*ssa.MakeSlice)     { v.count++ }
func (v *InstructionCountingOp) DoMakeMap(*ssa.MakeMap)         { v.count++ }
func (v *InstructionCountingOp) DoRange(*ssa.Range)             { v.count++ }
func (v *InstructionCountingOp) DoNext(*ssa.Next)               { v.count++ }
func (v *InstructionCountingOp) DoFieldAddr(*ssa.FieldAddr)     { v.count++ }
func (v *InstructionCountingOp) DoField(*ssa.Field)             { v.count++ }
func (v *InstructionCountingOp) DoIndexAddr(*ssa.IndexAddr)     { v.count++ }
func (v *InstructionCountingOp) DoIndex(*ssa.Index)             { v.count++ }
func (v *InstructionCountingOp) DoLookup(*ssa.Lookup)           { v.count++ }
func (v *InstructionCountingOp) DoMapUpdate(*ssa.MapUpdate)     { v.count++ }
func (v *InstructionCountingOp) DoTypeAssert(*ssa.TypeAssert)   { v.count++ }
func (v *InstructionCountingOp) DoMakeClosure(*ssa.MakeClosure) { v.count++ }
func (v *InstructionCountingOp) DoPhi(*ssa.Phi)                 { v.count++ }
func (v *InstructionCountingOp) DoSelect(*ssa.Select)           { v.count++ }

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
		RunDFS(op, function)
		// Don't report on second run
		op.report = false
		RunAllPaths(op, function)
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
