package taint

import (
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// intraProcedural is the main entry point of the intra procedural analysis.
func intraProcedural(tt *TrackingInfo, ptrAnalysis *pointer.Result, function *ssa.Function) {
	tracker := &taintTracker{
		trackingInfo: tt,
		pointerInfo:  ptrAnalysis,
		changeFlag:   true,
		blocksSeen:   map[*ssa.BasicBlock]struct{}{},
	}
	ssafuncs.RunForwardIterative(tracker, function)
}

// getTaintedValueOrigin returns a source and true if v is a tainted value, otherwise it returns (nil, false)
// Uses both the direct taint information in the taint tracking info, and the pointer taint information, i.e:
// - A value is tainted if it is directly tainted
// - A value is tainted if it is a pointer and some alias is tainted.
// The path parameter enables path-sensitivity. If path is "*", any path is accepted and the analysis
// over-approximates.
func (t *taintTracker) getTaintedValueOrigin(v ssa.Value, path string) (*Source, bool) {
	// The value is directly marked as tainted.
	n, ok := t.trackingInfo.taintedValues[v]
	if ok {
		// Check that any path or paths match
		if path == "*" || n.Path == path {
			return n, ok
		}
	}

	updateAsPtr := func(ptr pointer.Pointer) (*Source, bool) {
		ptsToSet := ptr.PointsTo()
		for otherPtsTo, source := range t.trackingInfo.taintedPointers {
			if ptsToSet.Intersects(*otherPtsTo) {
				t.taintValue(v, source)
				return source, true
			}
		}
		return nil, false
	}

	// Check direct queries
	if ptr, ptrExists := t.pointerInfo.Queries[v]; ptrExists {
		if node, tainted := updateAsPtr(ptr); tainted {
			return node, tainted
		}
	}

	// Check indirect queries
	if ptr, ptrExists := t.pointerInfo.IndirectQueries[v]; ptrExists {
		if node, tainted := updateAsPtr(ptr); tainted {
			return node, tainted
		}
	}

	return nil, false
}

func (t *taintTracker) taintAllAliases(source *Source, ptsToSet pointer.PointsToSet) {
	// Look at every value in the points-to set.
	for _, label := range ptsToSet.Labels() {
		if label != nil && label.Value() != nil {
			source.Path = label.Path()
			t.trackingInfo.taintedValues[label.Value()] = source
		}
	}
	t.trackingInfo.taintedPointers[&ptsToSet] = source
}

// taintValue marks the value v as tainted with origin taintOrigin
// if the value was not marked as tainted, it changes the changeFlag to true to indicate that the taint information
// has changed for the current pass
func (t *taintTracker) taintValue(v ssa.Value, source *Source) {
	if _, ok := t.trackingInfo.taintedValues[v]; ok {
		return
	}
	// v was not tainted before
	t.changeFlag = true

	t.trackingInfo.taintedValues[v] = source
	// Propagate to any other value that is an alias of v
	// By direct query
	if ptr, ptrExists := t.pointerInfo.Queries[v]; ptrExists {
		t.taintAllAliases(source, ptr.PointsTo())
	}
	// By indirect query
	if ptr, ptrExists := t.pointerInfo.IndirectQueries[v]; ptrExists {
		t.taintAllAliases(source, ptr.PointsTo())
	}
}

func (t *taintTracker) AddFlowToSink(source ssa.Instruction, sink ssa.Instruction) {
	if _, ok := t.trackingInfo.SinkFromSource[sink]; ok {
		return
	}
	if IntraProceduralPathExists(source, sink) {
		t.trackingInfo.SinkFromSource[sink] = source
	}
}

// Helpers for propagating taint

func simpleTransitiveTaintPropagation(t *taintTracker, in ssa.Value, out ssa.Value) {
	if n, ok := t.getTaintedValueOrigin(in, "*"); ok {
		t.taintValue(out, n)
	}
}

func pathSensitiveTaintPropagation(t *taintTracker, in ssa.Value, out ssa.Value, path string) {
	if n, ok := t.getTaintedValueOrigin(in, path); ok {
		t.taintValue(out, n)
	}
}

// callCommonTaint can be used for Call, Defer and Go that wrap a CallCommon.
func (t *taintTracker) callCommonTaint(callValue ssa.Value, callInstr ssa.Instruction, callCommon *ssa.CallCommon) {
	if isSourceNode(t.trackingInfo.config, callInstr.(ssa.Node)) { // type cast cannot fail
		source := NewSource(callInstr, TaintedVal, "")
		t.taintValue(callValue, source)
	}

	if isSinkNode(t.trackingInfo.config, callInstr.(ssa.Node)) {
		for _, arg := range callCommon.Args {
			if origin, ok := t.getTaintedValueOrigin(arg, "*"); ok && origin.IsTainted() {
				t.AddFlowToSink(origin.GetTaintSourceInstruction(), callInstr)
			}
		}
	}
	// Special cases: move somewhere else later.
	if callCommon.Value != nil {
		switch callCommon.Value.Name() {
		case "append":
			for _, arg := range callCommon.Args {
				simpleTransitiveTaintPropagation(t, arg, callValue)
			}
		}
	}
}

// Implement path sensitivity operations

func (t *taintTracker) NewBlock(block *ssa.BasicBlock) {
	t.changeFlag = false
	// If the block has not been visited yet, declare that information has changed.
	if _, ok := t.blocksSeen[block]; !ok {
		t.blocksSeen[block] = struct{}{}
		t.changeFlag = true
	}
}

func (t *taintTracker) ChangedOnEndBlock() bool {
	return t.changeFlag
}

// Below are all the interface functions to implement the InstrOp interface

func (t *taintTracker) DoCall(call *ssa.Call) {
	t.callCommonTaint(call, call, call.Common())
}

func (t *taintTracker) DoDefer(d *ssa.Defer) {
	t.callCommonTaint(d.Value(), d, d.Common())
}

func (t *taintTracker) DoGo(g *ssa.Go) {
	t.callCommonTaint(g.Value(), g, g.Common())
}

func (t *taintTracker) DoDebugRef(*ssa.DebugRef) {}

func (t *taintTracker) DoUnOp(x *ssa.UnOp) {
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoBinOp(binop *ssa.BinOp) {
	// If either operand is tainted, taint the value.
	// We might want more precision later.
	simpleTransitiveTaintPropagation(t, binop.X, binop)
	simpleTransitiveTaintPropagation(t, binop.Y, binop)
}

func (t *taintTracker) DoChangeInterface(x *ssa.ChangeInterface) {
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoChangeType(x *ssa.ChangeType) {
	// Changing type doesn't change taint
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoConvert(x *ssa.Convert) {
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoSliceArrayToPointer(x *ssa.SliceToArrayPointer) {
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoMakeInterface(x *ssa.MakeInterface) {
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoExtract(x *ssa.Extract) {
	// TODO: tuple index sensitive propagation
	simpleTransitiveTaintPropagation(t, x.Tuple, x)
	//  "Warning: The analysis is imprecise on tuples.\n"
}

func (t *taintTracker) DoSlice(x *ssa.Slice) {
	// Taking a slice propagates taint information
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoReturn(r *ssa.Return) {
	for _, result := range r.Results {
		if source, ok := t.getTaintedValueOrigin(result, "*"); ok && source.IsTainted() {
			t.AddFlowToSink(source.GetTaintSourceInstruction(), r)
		}
	}

}

func (t *taintTracker) DoRunDefers(*ssa.RunDefers) {
	// TODO: handle defers
	// "Warning: The analysis is unsound on defers.\n"
}

func (t *taintTracker) DoPanic(x *ssa.Panic) {
	// A panic is always a sink
	if isSinkNode(t.trackingInfo.config, x) {
		if origin, ok := t.getTaintedValueOrigin(x.X, "*"); ok && origin.IsTainted() {
			t.AddFlowToSink(origin.GetTaintSourceInstruction(), x)
		}
	}
}

func (t *taintTracker) DoSend(x *ssa.Send) {
	// Sending a tainted value over the channel taints the whole channel
	simpleTransitiveTaintPropagation(t, x.X, x.Chan)
}

func (t *taintTracker) DoStore(x *ssa.Store) {
	simpleTransitiveTaintPropagation(t, x.Val, x.Addr)
}

func (t *taintTracker) DoIf(*ssa.If) {
	// Do nothing
	// TODO: do we want to add path sensivity, i.e. conditional on tainted value taints all values in condition?
}

func (t *taintTracker) DoJump(*ssa.Jump) {
	// Do nothing
}

func (t *taintTracker) DoMakeChan(*ssa.MakeChan) {
	// Do nothing
}

func (t *taintTracker) DoAlloc(x *ssa.Alloc) {
	if isSourceNode(t.trackingInfo.config, x) {
		source := NewSource(x, TaintedVal, "")
		t.taintValue(x, source)
	}
}

func (t *taintTracker) DoMakeSlice(*ssa.MakeSlice) {
	// Do nothing
}

func (t *taintTracker) DoMakeMap(*ssa.MakeMap) {
	// Do nothing
}

func (t *taintTracker) DoRange(x *ssa.Range) {
	// An iterator over a tainted value is tainted
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoNext(x *ssa.Next) {
	simpleTransitiveTaintPropagation(t, x.Iter, x)
}

func (t *taintTracker) DoFieldAddr(x *ssa.FieldAddr) {
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
	pathSensitiveTaintPropagation(t, x.X, x, path)
}

func (t *taintTracker) DoField(x *ssa.Field) {
	path := "*" // over-approximation
	// Try to get precise field name to be field sensitive
	xTyp := x.X.Type().Underlying()
	if structTyp, ok := xTyp.(*types.Struct); ok {
		path = structTyp.Field(x.Field).Name()
	}
	// Taint is propagated if field of struct is tainted
	pathSensitiveTaintPropagation(t, x.X, x, path)
}

func (t *taintTracker) DoIndexAddr(x *ssa.IndexAddr) {
	// An indexing taints the value if either index or the indexed value is tainted
	simpleTransitiveTaintPropagation(t, x.Index, x)
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoIndex(x *ssa.Index) {
	// An indexing taints the value if either index or array is tainted
	simpleTransitiveTaintPropagation(t, x.Index, x)
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoLookup(x *ssa.Lookup) {
	simpleTransitiveTaintPropagation(t, x.X, x)
	simpleTransitiveTaintPropagation(t, x.Index, x)
}

func (t *taintTracker) DoMapUpdate(x *ssa.MapUpdate) {
	// Adding a tainted key or value in a map taints the whole map
	simpleTransitiveTaintPropagation(t, x.Key, x.Map)
	simpleTransitiveTaintPropagation(t, x.Value, x.Map)
}

func (t *taintTracker) DoTypeAssert(x *ssa.TypeAssert) {
	simpleTransitiveTaintPropagation(t, x.X, x)
}

func (t *taintTracker) DoMakeClosure(x *ssa.MakeClosure) {
	// TODO: build summary of closure
	// panic(x)
	// "Warning: The analysis does not support closures yet. Results may be unsound.\n"
}

func (t *taintTracker) DoPhi(phi *ssa.Phi) {
	for _, edge := range phi.Edges {
		simpleTransitiveTaintPropagation(t, edge, phi)
	}
}

func (t *taintTracker) DoSelect(x *ssa.Select) {
	//	"Warning: The analysis does not support select statements.\n"
	// panic(x)
}
