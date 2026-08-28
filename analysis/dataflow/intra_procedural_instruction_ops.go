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
	"context"
	"go/token"
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/lang"
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
func (state *IntraAnalysisState) DoCall(ctx context.Context, call *ssa.Call) {
	doBuiltinCall(ctx, state, call, call.Common(), call)
}

// DoDefer analyzes a ssa.Defer. Does nothing - defers are analyzed separately.
func (state *IntraAnalysisState) DoDefer(context.Context, *ssa.Defer) {
	// Defers will be handled when RunDefers are handled
}

// DoGo analyses a go call like any function call. Use the escape analysis if you care about concurrency.
func (state *IntraAnalysisState) DoGo(ctx context.Context, g *ssa.Go) {
	doBuiltinCall(ctx, state, g.Value(), g.Common(), g)
}

// DoDebugRef is a no-op
func (state *IntraAnalysisState) DoDebugRef(context.Context, *ssa.DebugRef) {
	// Do nothing, we ignore debug refs in SSA
}

// DoUnOp analyzes unary operations and checks the operator to see whether is a load or a channel receive
func (state *IntraAnalysisState) DoUnOp(ctx context.Context, x *ssa.UnOp) {
	if x.Op == token.MUL {
		transferCopy(ctx, state, x, x.X, x)
	}

	simpleTransfer(ctx, state, x, x.X, x)
}

// DoBinOp analyzes binary operations
func (state *IntraAnalysisState) DoBinOp(ctx context.Context, binop *ssa.BinOp) {
	// If either operand is tainted, taint the Value.
	// We might want more precision later.
	simpleTransfer(ctx, state, binop, binop.X, binop)
	simpleTransfer(ctx, state, binop, binop.Y, binop)
}

// DoChangeInterface analyses ssa.ChangeInterface (a simple transferCopy)
func (state *IntraAnalysisState) DoChangeInterface(ctx context.Context, x *ssa.ChangeInterface) {
	transferCopy(ctx, state, x, x.X, x)
}

// DoChangeType analyses ssa.ChangeType (a simple transferCopy)
func (state *IntraAnalysisState) DoChangeType(ctx context.Context, x *ssa.ChangeType) {
	// Changing type doesn't change taint
	transferCopy(ctx, state, x, x.X, x)
}

// DoConvert analyzes a ssa.DoConvert (a simpleTransfer)
func (state *IntraAnalysisState) DoConvert(ctx context.Context, x *ssa.Convert) {
	simpleTransfer(ctx, state, x, x.X, x)
}

// DoSliceArrayToPointer analyzes a ssa.SliceToArrayPointer (a simpleTransfer)
func (state *IntraAnalysisState) DoSliceArrayToPointer(ctx context.Context, x *ssa.SliceToArrayPointer) {
	simpleTransfer(ctx, state, x, x.X, x)
}

// DoMakeInterface analyzes a ssa.MakeInterface (a transferCopy)
func (state *IntraAnalysisState) DoMakeInterface(ctx context.Context, x *ssa.MakeInterface) {
	transferCopy(ctx, state, x, x.X, x)
}

// DoExtract analyzes a ssa.Extract (a transfer with path "")
func (state *IntraAnalysisState) DoExtract(ctx context.Context, x *ssa.Extract) {
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
		transfer(ctx, state, x, x.Tuple, x, "", NonIndexMark)
	} else {
		transfer(ctx, state, x, x.Tuple, x, "", NewIndex(x.Index))
	}
}

// DoSlice analyzes slicing operations
func (state *IntraAnalysisState) DoSlice(ctx context.Context, x *ssa.Slice) {
	// Taking a slice propagates taint information
	simpleTransfer(ctx, state, x, x.X, x)
}

// DoReturn is a no-op
func (state *IntraAnalysisState) DoReturn(context.Context, *ssa.Return) {
	// At a return instruction, nothing happens (there is no mark to propagate)
}

// DoRunDefers analyzes the defers of the function by simulating the defers stack
func (state *IntraAnalysisState) DoRunDefers(ctx context.Context, r *ssa.RunDefers) {
	err := state.doDefersStackSimulation(ctx, r)
	if err != nil {
		state.errors[r] = err
	}
}

// DoPanic is a no-op; panic are handled separately
func (state *IntraAnalysisState) DoPanic(context.Context, *ssa.Panic) {
}

// DoSend analyzes a send operation on a channel. This does not take concurrency into account
func (state *IntraAnalysisState) DoSend(ctx context.Context, x *ssa.Send) {
	// Sending a tainted Value over the channel taints the whole channel
	simpleTransfer(ctx, state, x, x.X, x.Chan)
}

// DoStore analyzes store operations
func (state *IntraAnalysisState) DoStore(ctx context.Context, x *ssa.Store) {
	transfer(ctx, state, x, x.Val, x.Addr, "", NonIndexMark)
	// Special store
	switch addr := x.Addr.(type) {
	case *ssa.FieldAddr:
		fieldInfo := analysisutil.FieldAddrFieldInfo(addr)
		if fieldInfo.IsEmbedded {
			transfer(ctx, state, x, x.Val, addr.X, "", NonIndexMark)
		} else {
			transfer(ctx, state, x, x.Val, addr.X, fieldInfo.FieldName, NonIndexMark)
		}
	}
}

// DoIf is a no-op
func (state *IntraAnalysisState) DoIf(context.Context, *ssa.If) {}

// DoJump is a no-op
func (state *IntraAnalysisState) DoJump(context.Context, *ssa.Jump) {
	// Do nothing
}

// DoMakeChan is a no-op
func (state *IntraAnalysisState) DoMakeChan(context.Context, *ssa.MakeChan) {
	// Do nothing
}

// DoAlloc is a no-op, unless that specific allocation needs to be tracked (the information will be deduced from
// the config)
func (state *IntraAnalysisState) DoAlloc(ctx context.Context, x *ssa.Alloc) {
	if state.shouldTrack != nil && state.shouldTrack(state.parentAnalyzerState, x) {
		state.markValue(ctx, x, x, "", state.flowInfo.GetNewMark(x, DefaultMark, nil, NonIndexMark))
	}
}

// DoMakeSlice is a no-op
func (state *IntraAnalysisState) DoMakeSlice(context.Context, *ssa.MakeSlice) {
	// Do nothing
}

// DoMakeMap is a no-op
func (state *IntraAnalysisState) DoMakeMap(context.Context, *ssa.MakeMap) {
	// Do nothing
}

// DoRange analyzes the range by simply transferring marks from the input of the range to the iterator
func (state *IntraAnalysisState) DoRange(ctx context.Context, x *ssa.Range) {
	// An iterator over a tainted Value is tainted
	transfer(ctx, state, x, x.X, x, "[*]", NonIndexMark)
}

// DoNext transfers marks from the input of next to the output
func (state *IntraAnalysisState) DoNext(ctx context.Context, x *ssa.Next) {
	simpleTransfer(ctx, state, x, x.Iter, x)
}

// DoFieldAddr analyzes field addressing operations, with field sensitivity
func (state *IntraAnalysisState) DoFieldAddr(ctx context.Context, x *ssa.FieldAddr) {
	// Propagate taint with field sensitivity
	field := "*" // over-approximation
	// Try to get precise field name to be field sensitive
	if eltTyp, ok := lang.TryDerefTyp(x.X.Type()); ok {
		if structTyp, ok := eltTyp.Underlying().(*types.Struct); ok {
			field = structTyp.Field(x.Field).Name()
		}
	}
	path := ""
	if field != "" {
		path = "." + field
	}
	transfer(ctx, state, x, x.X, x, path, NonIndexMark)
}

// DoField analyzes field operations, with field-sensitivity
func (state *IntraAnalysisState) DoField(ctx context.Context, x *ssa.Field) {
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
	transfer(ctx, state, x, x.X, x, path, NonIndexMark)
}

// DoIndexAddr analyzers operation where the address of an index is taken, with indexing sensitivity
func (state *IntraAnalysisState) DoIndexAddr(ctx context.Context, x *ssa.IndexAddr) {
	// An indexing taints the Value if either index or the indexed Value is tainted
	simpleTransfer(ctx, state, x, x.Index, x)
	transfer(ctx, state, x, x.X, x, "[*]", NonIndexMark)
}

// DoIndex analyzes indexing with indexing sensitivity
func (state *IntraAnalysisState) DoIndex(ctx context.Context, x *ssa.Index) {
	// An indexing taints the Value if either index or array is tainted
	simpleTransfer(ctx, state, x, x.Index, x)
	transfer(ctx, state, x, x.X, x, "[*]", NonIndexMark)
}

// DoLookup analyzes lookups without indexing sensitivity
func (state *IntraAnalysisState) DoLookup(ctx context.Context, x *ssa.Lookup) {
	simpleTransfer(ctx, state, x, x.X, x)
	recordAccessPathTransfer(state, x, x.X, x, projectTransform("[*]"))
	simpleTransfer(ctx, state, x, x.Index, x)
}

// DoMapUpdate analyzes map updates without indexing sensitivity
func (state *IntraAnalysisState) DoMapUpdate(ctx context.Context, x *ssa.MapUpdate) {
	// Adding a tainted key or Value in a map taints the whole map
	transferPre(ctx, state, x, x.Key, x.Map, "", NonIndexMark, true)
	transferPre(ctx, state, x, x.Value, x.Map, "", NonIndexMark, true)
}

// DoTypeAssert views type assertions as a simple transfer of marks
func (state *IntraAnalysisState) DoTypeAssert(ctx context.Context, x *ssa.TypeAssert) {
	simpleTransfer(ctx, state, x, x.X, x)
}

// DoMakeClosure analyzes closures using markClosureNode
func (state *IntraAnalysisState) DoMakeClosure(context.Context, *ssa.MakeClosure) {
}

// DoPhi transfers marks from all incoming edges to the phi-value
func (state *IntraAnalysisState) DoPhi(ctx context.Context, phi *ssa.Phi) {
	for _, edge := range phi.Edges {
		simpleTransfer(ctx, state, phi, edge, phi)
	}
}

// DoSelect iterates through each of the select states to apply the transfer function
func (state *IntraAnalysisState) DoSelect(ctx context.Context, x *ssa.Select) {
	for _, selectState := range x.States {
		switch selectState.Dir {
		case types.RecvOnly:
			simpleTransfer(ctx, state, x, selectState.Chan, x)
		case types.SendOnly:
			simpleTransfer(ctx, state, x, selectState.Send, selectState.Chan)
		default:
			panic("unexpected select channel type")
		}
	}
}
