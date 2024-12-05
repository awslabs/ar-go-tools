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

package dataflow

import (
	"go/token"
	"go/types"

	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/go/ssa"
)

// This file contains all the instruction operations implemented for the intraprocedural analysis.

// NewBlock is called upon each new visited block
func (state *IntraAnalysisState) NewBlock(block *ssa.BasicBlock) {
	state.changeFlag = false
	state.curBlock = block
	// If the block has not been visited yet, declare that information has changed.
	if !state.blocksSeen[block.Index] {
		state.blocksSeen[block.Index] = true
		state.changeFlag = true
	}
}

// ChangedOnEndBlock indicates whether the analysis state has changed when finishing a block
func (state *IntraAnalysisState) ChangedOnEndBlock() bool {
	if state != nil && state.postBlockCallback != nil {
		state.postBlockCallback(state)
	}
	return state.changeFlag
}

// Below are all the interface functions to implement the InstrOp interface

// DoCall analyzes a ssa.Call
func (state *IntraAnalysisState) DoCall(call *ssa.Call) {
	doBuiltinCall(state, call, call.Common(), call)
}

// DoDefer analyzes a ssa.Defer. Does nothing - defers are analyzed separately.
func (state *IntraAnalysisState) DoDefer(_ *ssa.Defer) {
	// Defers will be handled when RunDefers are handled
}

// DoGo analyses a go call like any function call. Use the escape analysis if you care about concurrency.
func (state *IntraAnalysisState) DoGo(g *ssa.Go) {
	doBuiltinCall(state, g.Value(), g.Common(), g)
}

// DoDebugRef is a no-op
func (state *IntraAnalysisState) DoDebugRef(*ssa.DebugRef) {
	// Do nothing, we ignore debug refs in SSA
}

// DoUnOp analyzes unary operations and checks the operator to see whether is a load or a channel receive
func (state *IntraAnalysisState) DoUnOp(x *ssa.UnOp) {
	if x.Op == token.MUL {
		transferCopy(state, x, x.X, x)
	}

	simpleTransfer(state, x, x.X, x)
}

// DoBinOp analyzes binary operations
func (state *IntraAnalysisState) DoBinOp(binop *ssa.BinOp) {
	// If either operand is tainted, taint the Value.
	// We might want more precision later.
	simpleTransfer(state, binop, binop.X, binop)
	simpleTransfer(state, binop, binop.Y, binop)
}

// DoChangeInterface analyses ssa.ChangeInterface (a simple transferCopy)
func (state *IntraAnalysisState) DoChangeInterface(x *ssa.ChangeInterface) {
	transferCopy(state, x, x.X, x)
}

// DoChangeType analyses ssa.ChangeType (a simple transferCopy)
func (state *IntraAnalysisState) DoChangeType(x *ssa.ChangeType) {
	// Changing type doesn't change taint
	transferCopy(state, x, x.X, x)
}

// DoConvert analyzes a ssa.DoConvert (a simpleTransfer)
func (state *IntraAnalysisState) DoConvert(x *ssa.Convert) {
	simpleTransfer(state, x, x.X, x)
}

// DoSliceArrayToPointer analyzes a ssa.SliceToArrayPointer (a simpleTransfer)
func (state *IntraAnalysisState) DoSliceArrayToPointer(x *ssa.SliceToArrayPointer) {
	simpleTransfer(state, x, x.X, x)
}

// DoMakeInterface analyzes a ssa.MakeInterface (a transferCopy)
func (state *IntraAnalysisState) DoMakeInterface(x *ssa.MakeInterface) {
	transferCopy(state, x, x.X, x)
}

// DoExtract analyzes a ssa.Extract (a transfer with path "")
func (state *IntraAnalysisState) DoExtract(x *ssa.Extract) {
	// tuples store intermediate results from:
	// - call returns
	// - next instructions
	// - select instructions
	// - lookup instructions
	// Since next, select, lookup instructions are not nodes in the graph, we have to be careful about
	// how extract interacts with them.
	isUntrackedTuple := false
	switch x.Tuple.(type) {
	case *ssa.Next, *ssa.Select, *ssa.Lookup:
		isUntrackedTuple = true
	}
	if isUntrackedTuple {
		transfer(state, x, x.Tuple, x, "", NonIndexMark)
	} else {
		transfer(state, x, x.Tuple, x, "", NewIndex(x.Index))
	}
}

// DoSlice analyzes slicing operations
func (state *IntraAnalysisState) DoSlice(x *ssa.Slice) {
	// Taking a slice propagates taint information
	simpleTransfer(state, x, x.X, x)
}

// DoReturn is a no-op
func (state *IntraAnalysisState) DoReturn(_ *ssa.Return) {
	// At a return instruction, nothing happens (there is no mark to propagate)
}

// DoRunDefers analyzes the defers of the function by simulating the defers stack
func (state *IntraAnalysisState) DoRunDefers(r *ssa.RunDefers) {
	err := state.doDefersStackSimulation(r)
	if err != nil {
		state.errors[r] = err
	}
}

// DoPanic is a no-op; panic are handled separately
func (state *IntraAnalysisState) DoPanic(_ *ssa.Panic) {
}

// DoSend analyzes a send operation on a channel. This does not take concurrency into account
func (state *IntraAnalysisState) DoSend(x *ssa.Send) {
	// Sending a tainted Value over the channel taints the whole channel
	simpleTransfer(state, x, x.X, x.Chan)
}

// DoStore analyzes store operations
func (state *IntraAnalysisState) DoStore(x *ssa.Store) {
	transfer(state, x, x.Val, x.Addr, "", NonIndexMark)
	// Special store
	switch addr := x.Addr.(type) {
	case *ssa.FieldAddr:
		fieldName, isEmbedded := analysisutil.FieldAddrFieldInfo(addr)
		if isEmbedded {
			transfer(state, x, x.Val, addr.X, "", NonIndexMark)
		} else {
			transfer(state, x, x.Val, addr.X, fieldName, NonIndexMark)
		}
	}
}

// DoIf is a no-op
func (state *IntraAnalysisState) DoIf(*ssa.If) {}

// DoJump is a no-op
func (state *IntraAnalysisState) DoJump(*ssa.Jump) {
	// Do nothing
}

// DoMakeChan is a no-op
func (state *IntraAnalysisState) DoMakeChan(*ssa.MakeChan) {
	// Do nothing
}

// DoAlloc is a no-op, unless that specific allocation needs to be tracked (the information will be deduced from
// the config)
func (state *IntraAnalysisState) DoAlloc(x *ssa.Alloc) {
	if state.shouldTrack(state.parentAnalyzerState, x) {
		state.markValue(x, x, "", state.flowInfo.GetNewMark(x, DefaultMark, nil, NonIndexMark))
	}
}

// DoMakeSlice is a no-op
func (state *IntraAnalysisState) DoMakeSlice(*ssa.MakeSlice) {
	// Do nothing
}

// DoMakeMap is a no-op
func (state *IntraAnalysisState) DoMakeMap(*ssa.MakeMap) {
	// Do nothing
}

// DoRange analyzes the range by simply transferring marks from the input of the range to the iterator
func (state *IntraAnalysisState) DoRange(x *ssa.Range) {
	// An iterator over a tainted Value is tainted
	transfer(state, x, x.X, x, "[*]", NonIndexMark)
}

// DoNext transfers marks from the input of next to the output
func (state *IntraAnalysisState) DoNext(x *ssa.Next) {
	simpleTransfer(state, x, x.Iter, x)
}

// DoFieldAddr analyzes field addressing operations, with field sensitivity
func (state *IntraAnalysisState) DoFieldAddr(x *ssa.FieldAddr) {
	// Propagate taint with field sensitivity
	field := "*" // over-approximation
	// Try to get precise field name to be field sensitive
	xTyp := x.X.Type().Underlying()
	if ptrTyp, ok := xTyp.(*types.Pointer); ok {
		eltTyp := ptrTyp.Elem().Underlying()
		if structTyp, ok := eltTyp.(*types.Struct); ok {
			field = structTyp.Field(x.Field).Name()
		}
	}
	path := ""
	if field != "" {
		path = "." + field
	}
	transfer(state, x, x.X, x, path, NonIndexMark)
}

// DoField analyzes field operations, with field-sensitivity
func (state *IntraAnalysisState) DoField(x *ssa.Field) {
	// Propagate taint with field sensitivity
	field := "" // over-approximation
	// Try to get precise field name to be field sensitive
	xTyp := x.X.Type().Underlying()
	if structTyp, ok := xTyp.(*types.Struct); ok {
		field = structTyp.Field(x.Field).Name()
	}
	path := ""
	if field != "" {
		path = "." + field
	}
	transfer(state, x, x.X, x, path, NonIndexMark)
}

// DoIndexAddr analyzers operation where the address of an index is taken, with indexing sensitivity
func (state *IntraAnalysisState) DoIndexAddr(x *ssa.IndexAddr) {
	// An indexing taints the Value if either index or the indexed Value is tainted
	simpleTransfer(state, x, x.Index, x)
	transfer(state, x, x.X, x, "[*]", NonIndexMark)
}

// DoIndex analyzes indexing with indexing sensitivity
func (state *IntraAnalysisState) DoIndex(x *ssa.Index) {
	// An indexing taints the Value if either index or array is tainted
	simpleTransfer(state, x, x.Index, x)
	transfer(state, x, x.X, x, "[*]", NonIndexMark)
}

// DoLookup analyzes lookups without indexing sensitivity
func (state *IntraAnalysisState) DoLookup(x *ssa.Lookup) {
	simpleTransfer(state, x, x.X, x)
	simpleTransfer(state, x, x.Index, x)
}

// DoMapUpdate analyzes map updates without indexing sensitivity
func (state *IntraAnalysisState) DoMapUpdate(x *ssa.MapUpdate) {
	// Adding a tainted key or Value in a map taints the whole map
	transferPre(state, x, x.Key, x.Map, "", NonIndexMark, true)
	transferPre(state, x, x.Value, x.Map, "", NonIndexMark, true)
}

// DoTypeAssert views type assertions as a simple transfer of marks
func (state *IntraAnalysisState) DoTypeAssert(x *ssa.TypeAssert) {
	simpleTransfer(state, x, x.X, x)
}

// DoMakeClosure analyzes closures using markClosureNode
func (state *IntraAnalysisState) DoMakeClosure(_ *ssa.MakeClosure) {
}

// DoPhi transfers marks from all incoming edges to the phi-value
func (state *IntraAnalysisState) DoPhi(phi *ssa.Phi) {
	for _, edge := range phi.Edges {
		simpleTransfer(state, phi, edge, phi)
	}
}

// DoSelect iterates through each of the select states to apply the transfer function
func (state *IntraAnalysisState) DoSelect(x *ssa.Select) {
	for _, selectState := range x.States {
		switch selectState.Dir {
		case types.RecvOnly:
			simpleTransfer(state, x, selectState.Chan, x)
		case types.SendOnly:
			simpleTransfer(state, x, selectState.Send, selectState.Chan)
		default:
			panic("unexpected select channel type")
		}
	}
}
