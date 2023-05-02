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
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// This file contains all the instruction operations implemented for the intraprocedural analysis.

func (state *AnalysisState) NewBlock(block *ssa.BasicBlock) {
	state.changeFlag = false
	state.curBlock = block
	// If the block has not been visited yet, declare that information has changed.
	if !state.blocksSeen[block] {
		state.blocksSeen[block] = true
		state.changeFlag = true
	}
}

func (state *AnalysisState) ChangedOnEndBlock() bool {
	if state != nil && state.postBlockCallback != nil {
		state.postBlockCallback(state)
	}
	return state.changeFlag
}

// Below are all the interface functions to implement the InstrOp interface

func (state *AnalysisState) DoCall(call *ssa.Call) {
	state.callCommonMark(call, call, call.Common())
}

func (state *AnalysisState) DoDefer(_ *ssa.Defer) {
	// Defers will be handled when RunDefers are handled
}

func (state *AnalysisState) DoGo(g *ssa.Go) {
	state.callCommonMark(g.Value(), g, g.Common())
}

func (state *AnalysisState) DoDebugRef(*ssa.DebugRef) {
	// Do nothing, we ignore debug refs in SSA
}

func (state *AnalysisState) DoUnOp(x *ssa.UnOp) {
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoBinOp(binop *ssa.BinOp) {
	// If either operand is tainted, taint the value.
	// We might want more precision later.
	simpleTransfer(state, binop, binop.X, binop)
	simpleTransfer(state, binop, binop.Y, binop)
}

func (state *AnalysisState) DoChangeInterface(x *ssa.ChangeInterface) {
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoChangeType(x *ssa.ChangeType) {
	// Changing type doesn'state change taint
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoConvert(x *ssa.Convert) {
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoSliceArrayToPointer(x *ssa.SliceToArrayPointer) {
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoMakeInterface(x *ssa.MakeInterface) {
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoExtract(x *ssa.Extract) {
	transfer(state, x, x.Tuple, x, "", x.Index)
}

func (state *AnalysisState) DoSlice(x *ssa.Slice) {
	// Taking a slice propagates taint information
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoReturn(r *ssa.Return) {
	// At a return instruction, nothing happens (there is no mark to propagate)
}

func (state *AnalysisState) DoRunDefers(r *ssa.RunDefers) {
	err := state.doDefersStackSimulation(r)
	if err != nil {
		state.errors[r] = err
	}
}

func (state *AnalysisState) DoPanic(x *ssa.Panic) {
	// TODO figure out how to handle this
	// state.errors[x] = fmt.Errorf("panic is not handled yet")
}

func (state *AnalysisState) DoSend(x *ssa.Send) {
	// Sending a tainted value over the channel taints the whole channel
	simpleTransfer(state, x, x.X, x.Chan)
}

func (state *AnalysisState) DoStore(x *ssa.Store) {
	transfer(state, x, x.Val, x.Addr, "*", -1)
	// Special store
	switch addr := x.Addr.(type) {
	case *ssa.FieldAddr:
		transfer(state, x, x.Val, addr.X, FieldAddrFieldName(addr), -1)
	}
}

func (state *AnalysisState) DoIf(*ssa.If) {
	// Do nothing
	// TODO: do we want to add path sensitivity, i.e. conditional on tainted value taints all values in condition?
}

func (state *AnalysisState) DoJump(*ssa.Jump) {
	// Do nothing
}

func (state *AnalysisState) DoMakeChan(*ssa.MakeChan) {
	// Do nothing
}

func (state *AnalysisState) DoAlloc(x *ssa.Alloc) {
	if state.shouldTrack(state.flowInfo.Config, x) {
		state.markValue(x, x, NewMark(x, DefaultMark, "", nil, -1))
	}
	// An allocation may be a mark
	state.optionalSyntheticNode(x, x, x)
}

func (state *AnalysisState) DoMakeSlice(*ssa.MakeSlice) {
	// Do nothing
}

func (state *AnalysisState) DoMakeMap(*ssa.MakeMap) {
	// Do nothing
}

func (state *AnalysisState) DoRange(x *ssa.Range) {
	// An iterator over a tainted value is tainted
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoNext(x *ssa.Next) {
	simpleTransfer(state, x, x.Iter, x)
}

func (state *AnalysisState) DoFieldAddr(x *ssa.FieldAddr) {
	// A FieldAddr may be a mark
	state.optionalSyntheticNode(x, x, x)

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
	// Taint is propagated if field of struct is tainted
	transfer(state, x, x.X, x, field, -1)
}

func (state *AnalysisState) DoField(x *ssa.Field) {
	// A field may be a mark
	state.optionalSyntheticNode(x, x, x)

	// Propagate taint with field sensitivity
	field := "*" // over-approximation
	// Try to get precise field name to be field sensitive
	xTyp := x.X.Type().Underlying()
	if structTyp, ok := xTyp.(*types.Struct); ok {
		field = structTyp.Field(x.Field).Name()
	}
	// Taint is propagated if field of struct is tainted
	transfer(state, x, x.X, x, field, -1)
}

func (state *AnalysisState) DoIndexAddr(x *ssa.IndexAddr) {
	// An indexing taints the value if either index or the indexed value is tainted
	simpleTransfer(state, x, x.Index, x)
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoIndex(x *ssa.Index) {
	// An indexing taints the value if either index or array is tainted
	simpleTransfer(state, x, x.Index, x)
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoLookup(x *ssa.Lookup) {
	simpleTransfer(state, x, x.X, x)
	simpleTransfer(state, x, x.Index, x)
}

func (state *AnalysisState) DoMapUpdate(x *ssa.MapUpdate) {
	// Adding a tainted key or value in a map taints the whole map
	simpleTransfer(state, x, x.Key, x.Map)
	simpleTransfer(state, x, x.Value, x.Map)
}

func (state *AnalysisState) DoTypeAssert(x *ssa.TypeAssert) {
	simpleTransfer(state, x, x.X, x)
}

func (state *AnalysisState) DoMakeClosure(x *ssa.MakeClosure) {
	state.addClosureNode(x)
}

func (state *AnalysisState) DoPhi(phi *ssa.Phi) {
	for _, edge := range phi.Edges {
		simpleTransfer(state, phi, edge, phi)
	}
}

func (state *AnalysisState) DoSelect(x *ssa.Select) {
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
