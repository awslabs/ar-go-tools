package taint

import (
	"fmt"
	"go/types"
	"golang.org/x/tools/go/ssa"
)

// This file contains all the instruction operations implemented for the intraprocedural analysis.

func (t *stateTracker) NewBlock(block *ssa.BasicBlock) {
	t.changeFlag = false
	// If the block has not been visited yet, declare that information has changed.
	if !t.blocksSeen[block] {
		t.blocksSeen[block] = true
		t.changeFlag = true
	}
}

func (t *stateTracker) ChangedOnEndBlock() bool {
	return t.changeFlag
}

// Below are all the interface functions to implement the InstrOp interface

func (t *stateTracker) DoCall(call *ssa.Call) {
	t.callCommonTaint(call, call, call.Common())
}

func (t *stateTracker) DoDefer(_ *ssa.Defer) {
	// Defers will be handled when RunDefers are handled
}

func (t *stateTracker) DoGo(g *ssa.Go) {
	t.callCommonTaint(g.Value(), g, g.Common())
}

func (t *stateTracker) DoDebugRef(*ssa.DebugRef) {
	// Do nothing, we ignore debug refs in SSA
}

func (t *stateTracker) DoUnOp(x *ssa.UnOp) {
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoBinOp(binop *ssa.BinOp) {
	// If either operand is tainted, taint the value.
	// We might want more precision later.
	simpleTransitiveMarkPropagation(t, binop.X, binop)
	simpleTransitiveMarkPropagation(t, binop.Y, binop)
}

func (t *stateTracker) DoChangeInterface(x *ssa.ChangeInterface) {
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoChangeType(x *ssa.ChangeType) {
	// Changing type doesn't change taint
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoConvert(x *ssa.Convert) {
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoSliceArrayToPointer(x *ssa.SliceToArrayPointer) {
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoMakeInterface(x *ssa.MakeInterface) {
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoExtract(x *ssa.Extract) {
	// TODO: tuple index sensitive propagation
	simpleTransitiveMarkPropagation(t, x.Tuple, x)
	//  "Warning: The analysis is imprecise on tuples.\n"
}

func (t *stateTracker) DoSlice(x *ssa.Slice) {
	// Taking a slice propagates taint information
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoReturn(r *ssa.Return) {
	for _, result := range r.Results {
		for _, origin := range t.getMarkedValueOrigins(result, "*") {
			t.summary.addReturnEdge(origin, r)
		}
	}
}

func (t *stateTracker) DoRunDefers(r *ssa.RunDefers) {
	err := t.doDefersStackSimulation(r)
	if err != nil {
		t.errors[r] = err
	}
}

func (t *stateTracker) DoPanic(x *ssa.Panic) {
	// A panic is always a sink
	if isSinkNode(t.taintInfo.config, x) {
		for _, origin := range t.getMarkedValueOrigins(x.X, "*") {
			if origin.IsTainted() {
				t.AddFlowToSink(origin, x)
			}
		}
	}
}

func (t *stateTracker) DoSend(x *ssa.Send) {
	// Sending a tainted value over the channel taints the whole channel
	simpleTransitiveMarkPropagation(t, x.X, x.Chan)
}

func (t *stateTracker) DoStore(x *ssa.Store) {
	simpleTransitiveMarkPropagation(t, x.Val, x.Addr)
}

func (t *stateTracker) DoIf(*ssa.If) {
	// Do nothing
	// TODO: do we want to add path sensitivity, i.e. conditional on tainted value taints all values in condition?
}

func (t *stateTracker) DoJump(*ssa.Jump) {
	// Do nothing
}

func (t *stateTracker) DoMakeChan(*ssa.MakeChan) {
	// Do nothing
}

func (t *stateTracker) DoAlloc(x *ssa.Alloc) {
	if isSourceNode(t.taintInfo.config, x) {
		source := NewSource(x, TaintedVal, "")
		t.markValue(x, source)
	}
}

func (t *stateTracker) DoMakeSlice(*ssa.MakeSlice) {
	// Do nothing
}

func (t *stateTracker) DoMakeMap(*ssa.MakeMap) {
	// Do nothing
}

func (t *stateTracker) DoRange(x *ssa.Range) {
	// An iterator over a tainted value is tainted
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoNext(x *ssa.Next) {
	simpleTransitiveMarkPropagation(t, x.Iter, x)
}

func (t *stateTracker) DoFieldAddr(x *ssa.FieldAddr) {
	path := "*" // over-approximation
	// Try to get precise field name to be field sensitive
	xTyp := x.X.Type().Underlying()
	if ptrTyp, ok := xTyp.(*types.Pointer); ok {
		eltTyp := ptrTyp.Elem().Underlying()
		if structTyp, ok := eltTyp.(*types.Struct); ok {
			path = structTyp.Field(x.Field).Name()
		}
	}
	// Taint is propagated if field of struct is tainted
	pathSensitiveMarkPropagation(t, x.X, x, path)
}

func (t *stateTracker) DoField(x *ssa.Field) {
	path := "*" // over-approximation
	// Try to get precise field name to be field sensitive
	xTyp := x.X.Type().Underlying()
	if structTyp, ok := xTyp.(*types.Struct); ok {
		path = structTyp.Field(x.Field).Name()
	}
	// Taint is propagated if field of struct is tainted
	pathSensitiveMarkPropagation(t, x.X, x, path)
}

func (t *stateTracker) DoIndexAddr(x *ssa.IndexAddr) {
	// An indexing taints the value if either index or the indexed value is tainted
	simpleTransitiveMarkPropagation(t, x.Index, x)
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoIndex(x *ssa.Index) {
	// An indexing taints the value if either index or array is tainted
	simpleTransitiveMarkPropagation(t, x.Index, x)
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoLookup(x *ssa.Lookup) {
	simpleTransitiveMarkPropagation(t, x.X, x)
	simpleTransitiveMarkPropagation(t, x.Index, x)
}

func (t *stateTracker) DoMapUpdate(x *ssa.MapUpdate) {
	// Adding a tainted key or value in a map taints the whole map
	simpleTransitiveMarkPropagation(t, x.Key, x.Map)
	simpleTransitiveMarkPropagation(t, x.Value, x.Map)
}

func (t *stateTracker) DoTypeAssert(x *ssa.TypeAssert) {
	simpleTransitiveMarkPropagation(t, x.X, x)
}

func (t *stateTracker) DoMakeClosure(x *ssa.MakeClosure) {
	// TODO: build summary of closure
	err := fmt.Errorf("encountered a closure but ignored it: analysis unsound")
	t.errors[x] = err
}

func (t *stateTracker) DoPhi(phi *ssa.Phi) {
	for _, edge := range phi.Edges {
		simpleTransitiveMarkPropagation(t, edge, phi)
	}
}

func (t *stateTracker) DoSelect(x *ssa.Select) {
	err := fmt.Errorf("encountered a select but ignored it: analysis unsound")
	t.errors[x] = err
}
