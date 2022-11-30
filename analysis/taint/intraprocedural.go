package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// This file implements the intra-procedural analysis. This analysis pass inspects a single function and constructs:
// - a dataflow summary of the function
// - the intra-procedural paths from a source to a sink
// This file `intraprocedural.go` contains all the logic of the analysis and the transfer functions
// called to handle each instruction.
// The `intraprocedural_instruction_ops.go` file contains all the functions that define how instructions in the function
// are handled.

// stateTracker contains the information used by the intra-procedural taint analysis. The main components modified by
// the analysis  are the taintInfo and the argFlows fields, which contain information about taint flows and argument
// flows respectively.
type stateTracker struct {
	taintInfo   *FlowInformation         // the taint information for the analysis
	pointerInfo *pointer.Result          // the pointer analysis results used by the taint analysis
	changeFlag  bool                     // a flag to keep track of changes in the analysis state
	blocksSeen  map[*ssa.BasicBlock]bool // a map to keep track of blocks seen during the analysis
	errors      map[ssa.Node]error       // we don't panic during the analysis, but accumulate errors
	summary     *SummaryGraph            // summary is the function summary currently being built
}

// IntraResult holds the results of the intra-procedural analysis.
type IntraResult struct {
	IntraPaths map[ssa.Instruction]map[ssa.Instruction]bool // IntraPaths are the intra-procedural paths from sources
	// to sinks. This might disappear as the inter-procedural analysis should subsume it, but it is kept for now as
	// the user has the option to turn off the inter-procedural pass in the analysis.
	Summary *SummaryGraph // Summary is the procedure summary built by the analysis
}

// intraProcedural is the main entry point of the intra procedural analysis.
func intraProcedural(cfg *config.Config, ptrAnalysis *pointer.Result, function *ssa.Function, runit bool) (IntraResult, error) {
	sm := NewSummaryGraph(function, ptrAnalysis.CallGraph.Nodes[function])
	tt := NewFlowInfo(cfg)
	tracker := &stateTracker{
		taintInfo:   tt,
		pointerInfo: ptrAnalysis,
		changeFlag:  true,
		blocksSeen:  map[*ssa.BasicBlock]bool{},
		errors:      map[ssa.Node]error{},
		summary:     sm,
	}

	// The parameters of the function are marked as Parameter
	for _, param := range function.Params {
		tt.AddSource(param, NewSource(param, Parameter, "*"))
	}

	// Run the analysis. Once the analysis terminates, mark the summary as constructed.
	if runit {
		ssafuncs.RunForwardIterative(tracker, function)
		sm.constructed = true
	}

	// If we have errors, return one (TODO: we'll decide how to handle them later)
	for _, err := range tracker.errors {
		return IntraResult{}, fmt.Errorf("error in intraprocedural analysis: %w", err)
	}
	return IntraResult{IntraPaths: tt.SinkSources, Summary: sm}, nil
}

// getMarkedValueOrigins returns a source and true if v is a marked value, otherwise it returns (nil, false)
// Uses both the direct taint information in the taint tracking info, and the pointer taint information, i.e:
// - A value is marked if it is directly marked
// - A value is marked if it is a pointer and some alias is marked.
// The path parameter enables path-sensitivity. If path is "*", any path is accepted and the analysis
// over-approximates.
func (t *stateTracker) getMarkedValueOrigins(v ssa.Value, path string) []Source {
	var origins []Source
	// when the value is directly marked as tainted.
	for source := range t.taintInfo.markedValues[v] {
		if path == "*" || source.RegionPath == path {
			origins = append(origins, source)
		}
	}

	// when the value's aliases is marked by intersecting with another marked values aliases
	if ptr := t.getAnyPointer(v); ptr != nil {
		ptsToSet := ptr.PointsTo()
		for otherPtsTo, source := range t.taintInfo.markedPointers {
			if ptsToSet.Intersects(*otherPtsTo) {
				t.markValue(v, source)
				origins = append(origins, source)
			}
		}
	}
	return origins
}

// getAnyPointer returns the pointer to x according to the pointer analysis
func (t *stateTracker) getAnyPointer(x ssa.Value) *pointer.Pointer {
	// pointer information in Queries and IndirectQueries should be mutually exclusive, but we run both.
	if ptr, ptrExists := t.pointerInfo.Queries[x]; ptrExists {
		return &ptr
	}
	// Check indirect queries
	if ptr, ptrExists := t.pointerInfo.IndirectQueries[x]; ptrExists {
		return &ptr
	}
	return nil
}

// paramAliases returns the list of parameters of the function the value x aliases to.
// TODO: cache some of the information obtained by this query
func (t *stateTracker) paramAliases(x ssa.Value) []ssa.Value {
	var aliasedParams []ssa.Value
	for _, param := range t.summary.parent.Params {
		if x == param {
			aliasedParams = append(aliasedParams, param)
		} else {
			paramPtr := t.getAnyPointer(param)
			xPtr := t.getAnyPointer(x)
			if paramPtr != nil && xPtr != nil && paramPtr.PointsTo().Intersects(xPtr.PointsTo()) {
				aliasedParams = append(aliasedParams, param)
			}
		}
	}
	return aliasedParams
}

// checkCopyIntoArgs checks whether the source in is copying or writing into a value that aliases with
// one of the function's parameters. This keeps tracks of data flows to the function parameters that a
// caller might see.
func (t *stateTracker) checkCopyIntoArgs(in Source, out ssa.Value) {
	for _, aliasedParam := range t.paramAliases(out) {
		t.summary.addParamEdge(in, aliasedParam.(ssa.Node)) // type conversion is safe
	}
}

// markAllAliases marks all the aliases of the pointer set using the source
func (t *stateTracker) markAllAliases(source Source, ptsToSet pointer.PointsToSet) {
	// Look at every value in the points-to set.
	for _, label := range ptsToSet.Labels() {
		if label != nil && label.Value() != nil {
			source.RegionPath = label.Path()
			t.taintInfo.AddSource(label.Value(), source)
		}
	}
	t.taintInfo.markedPointers[&ptsToSet] = source
}

// markValue marks the value v as tainted with origin taintOrigin
// if the value was not marked as tainted, it changes the changeFlag to true to indicate that the taint information
// has changed for the current pass
func (t *stateTracker) markValue(v ssa.Value, source Source) {
	if t.taintInfo.HasSource(v, source) {
		return
	}
	// v was not tainted before
	t.changeFlag = t.taintInfo.AddSource(v, source)
	// Propagate to any other value that is an alias of v
	// By direct query
	if ptr, ptrExists := t.pointerInfo.Queries[v]; ptrExists {
		t.markAllAliases(source, ptr.PointsTo())
	}
	// By indirect query
	if ptr, ptrExists := t.pointerInfo.IndirectQueries[v]; ptrExists {
		t.markAllAliases(source, ptr.PointsTo())
	}
}

func (t *stateTracker) AddFlowToSink(source Source, sink ssa.Instruction) {
	// A flow from a tainted source to a sink is added in the taint tracking info
	if source.IsTainted() {
		sourceInstr := source.Node.(ssa.Instruction) // a taint-source must be an instruction
		if t.taintInfo.HasSinkSourcePair(sink, sourceInstr) {
			return // skip computing paths
		}
		if IntraProceduralPathExists(sourceInstr, sink) {
			_ = t.taintInfo.AddSinkSourcePair(sink, sourceInstr)
		}
	}
}

// Helpers for propagating taint

// simpleTransitiveMarkPropagation  propagates all the marks from in to out
func simpleTransitiveMarkPropagation(t *stateTracker, in ssa.Value, out ssa.Value) {
	pathSensitiveMarkPropagation(t, in, out, "*")
}

// pathSensitiveMarkPropagation propagates all the marks from in to out with the object path string
func pathSensitiveMarkPropagation(t *stateTracker, in ssa.Value, out ssa.Value, path string) {
	for _, origin := range t.getMarkedValueOrigins(in, path) {
		t.markValue(out, origin)
		t.checkCopyIntoArgs(origin, out)
	}
}

// callCommonTaint can be used for Call, Defer and Go that wrap a CallCommon.
func (t *stateTracker) callCommonTaint(callValue ssa.Value, callInstr ssa.CallInstruction, callCommon *ssa.CallCommon) {
	// Special cases: move somewhere else later.
	if callCommon.Value != nil {
		switch callCommon.Value.Name() {
		// for append, we simply propagate the taint like in a binary operator
		case "append":
			for _, arg := range callCommon.Args {
				simpleTransitiveMarkPropagation(t, arg, callValue)
			}
			return

		// for len, we also propagate the taint. This may not be necessary
		case "len":
			for _, arg := range callCommon.Args {
				simpleTransitiveMarkPropagation(t, arg, callValue)
			}
			return
		}
	}
	// Add call instruction to summary, in case it hasn't been added through callgraph
	t.summary.addCallInstr(callInstr)
	// Check if node is source according to config
	sourceType := CallReturn
	if isSourceNode(t.taintInfo.config, callInstr.(ssa.Node)) { // type cast cannot fail
		sourceType += TaintedVal
	}
	// Mark call
	t.markValue(callValue, NewSource(callInstr.(ssa.Node), sourceType, ""))

	callIsSink := isSinkNode(t.taintInfo.config, callInstr.(ssa.Node))

	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range callCommon.Args {
		// Mark call argument
		t.markValue(arg, NewQualifierSource(callInstr.(ssa.Node), arg, CallSiteArg, ""))

		for _, source := range t.getMarkedValueOrigins(arg, "*") {

			if source.IsTainted() {
				if callIsSink {
					// This is an intra-procedural path from a source to a sink
					t.AddFlowToSink(source, callInstr)
				}
			}
			// Add any necessary edge in the summary flow graph (incoming edges at call site)
			pathExists := true
			if sourceInstr, ok := source.Node.(ssa.Instruction); ok {
				pathExists = IntraProceduralPathExists(sourceInstr, callInstr)
			}
			if pathExists {
				t.summary.addCallArgEdge(source, callInstr, arg)
				for _, x := range t.paramAliases(arg) {
					t.summary.addParamEdge(source, x.(ssa.Node))
				}
			}
		}
	}
}
