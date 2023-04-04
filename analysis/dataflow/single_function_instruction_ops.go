package dataflow

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// This file contains all the instruction operations implemented for the intraprocedural analysis.

func (state *analysisState) NewBlock(block *ssa.BasicBlock) {
	state.changeFlag = false
	// If the block has not been visited yet, declare that information has changed.
	if !state.blocksSeen[block] {
		state.blocksSeen[block] = true
		state.changeFlag = true
	}
}

func (state *analysisState) ChangedOnEndBlock() bool {
	return state.changeFlag
}

// Below are all the interface functions to implement the InstrOp interface

func (state *analysisState) DoCall(call *ssa.Call) {
	state.callCommonMark(call, call, call.Common())
}

func (state *analysisState) DoDefer(_ *ssa.Defer) {
	// Defers will be handled when RunDefers are handled
}

func (state *analysisState) DoGo(g *ssa.Go) {
	state.callCommonMark(g.Value(), g, g.Common())
}

func (state *analysisState) DoDebugRef(*ssa.DebugRef) {
	// Do nothing, we ignore debug refs in SSA
}

func (state *analysisState) DoUnOp(x *ssa.UnOp) {
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoBinOp(binop *ssa.BinOp) {
	// If either operand is tainted, taint the value.
	// We might want more precision later.
	simpleTransitiveMarkPropagation(state, binop, binop.X, binop)
	simpleTransitiveMarkPropagation(state, binop, binop.Y, binop)
}

func (state *analysisState) DoChangeInterface(x *ssa.ChangeInterface) {
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoChangeType(x *ssa.ChangeType) {
	// Changing type doesn'state change taint
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoConvert(x *ssa.Convert) {
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoSliceArrayToPointer(x *ssa.SliceToArrayPointer) {
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoMakeInterface(x *ssa.MakeInterface) {
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoExtract(x *ssa.Extract) {
	// TODO: tuple index sensitive propagation
	simpleTransitiveMarkPropagation(state, x, x.Tuple, x)
}

func (state *analysisState) DoSlice(x *ssa.Slice) {
	// Taking a slice propagates taint information
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoReturn(r *ssa.Return) {
	for _, result := range r.Results {
		for _, origin := range state.getMarkedValues(r, result, "*") {
			state.summary.AddReturnEdge(origin, r, nil)
		}
	}
}

func (state *analysisState) DoRunDefers(r *ssa.RunDefers) {
	err := state.doDefersStackSimulation(r)
	if err != nil {
		state.errors[r] = err
	}
}

func (state *analysisState) DoPanic(x *ssa.Panic) {
	// TODO figure out how to handle this
	// state.errors[x] = fmt.Errorf("panic is not handled yet")
}

func (state *analysisState) DoSend(x *ssa.Send) {
	// Sending a tainted value over the channel taints the whole channel
	simpleTransitiveMarkPropagation(state, x, x.X, x.Chan)
}

func (state *analysisState) DoStore(x *ssa.Store) {
	pathSensitiveMarkPropagation(state, x, x.Val, x.Addr, "*")
	// Special store
	switch addr := x.Addr.(type) {
	case *ssa.FieldAddr:
		pathSensitiveMarkPropagation(state, x, x.Val, addr.X, FieldAddrFieldName(addr))
	}
}

func (state *analysisState) DoIf(*ssa.If) {
	// Do nothing
	// TODO: do we want to add path sensitivity, i.e. conditional on tainted value taints all values in condition?
}

func (state *analysisState) DoJump(*ssa.Jump) {
	// Do nothing
}

func (state *analysisState) DoMakeChan(*ssa.MakeChan) {
	// Do nothing
}

func (state *analysisState) DoAlloc(x *ssa.Alloc) {
	if state.shouldTrack(state.flowInfo.Config, x) {
		state.markValue(x, x, NewMark(x, DefaultMark, ""))
	}
	// An allocation may be a mark
	state.optionalSyntheticNode(x, x, x)
}

func (state *analysisState) DoMakeSlice(*ssa.MakeSlice) {
	// Do nothing
}

func (state *analysisState) DoMakeMap(*ssa.MakeMap) {
	// Do nothing
}

func (state *analysisState) DoRange(x *ssa.Range) {
	// An iterator over a tainted value is tainted
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoNext(x *ssa.Next) {
	simpleTransitiveMarkPropagation(state, x, x.Iter, x)
}

func (state *analysisState) DoFieldAddr(x *ssa.FieldAddr) {
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
	pathSensitiveMarkPropagation(state, x, x.X, x, field)
}

func (state *analysisState) DoField(x *ssa.Field) {
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
	pathSensitiveMarkPropagation(state, x, x.X, x, field)
}

func (state *analysisState) DoIndexAddr(x *ssa.IndexAddr) {
	// An indexing taints the value if either index or the indexed value is tainted
	simpleTransitiveMarkPropagation(state, x, x.Index, x)
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoIndex(x *ssa.Index) {
	// An indexing taints the value if either index or array is tainted
	simpleTransitiveMarkPropagation(state, x, x.Index, x)
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoLookup(x *ssa.Lookup) {
	simpleTransitiveMarkPropagation(state, x, x.X, x)
	simpleTransitiveMarkPropagation(state, x, x.Index, x)
}

func (state *analysisState) DoMapUpdate(x *ssa.MapUpdate) {
	// Adding a tainted key or value in a map taints the whole map
	simpleTransitiveMarkPropagation(state, x, x.Key, x.Map)
	simpleTransitiveMarkPropagation(state, x, x.Value, x.Map)
}

func (state *analysisState) DoTypeAssert(x *ssa.TypeAssert) {
	simpleTransitiveMarkPropagation(state, x, x.X, x)
}

func (state *analysisState) DoMakeClosure(x *ssa.MakeClosure) {
	state.addClosureNode(x)
}

func (state *analysisState) DoPhi(phi *ssa.Phi) {
	for _, edge := range phi.Edges {
		simpleTransitiveMarkPropagation(state, phi, edge, phi)
	}
}

func (state *analysisState) DoSelect(x *ssa.Select) {
	for _, selectState := range x.States {
		switch selectState.Dir {
		case types.RecvOnly:
			simpleTransitiveMarkPropagation(state, x, selectState.Chan, x)
		case types.SendOnly:
			simpleTransitiveMarkPropagation(state, x, selectState.Send, selectState.Chan)
		default:
			panic("unexpected select channel type")
		}
	}
}
