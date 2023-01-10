package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"go/types"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"os"
)

// This file implements the single function analysis. This analysis pass inspects a single function and constructs:
// - a dataflow summary of the function
// - the intra-procedural paths from a source to a sink
// This file `single_function.go` contains all the logic of the analysis and the transfer functions
// called to handle each instruction.
// The `single_function_instruction_ops.go` file contains all the functions that define how instructions in the function
// are handled.

// stateTracker contains the information used by the intra-procedural taint analysis. The main components modified by
// the analysis  are the taintInfo and the argFlows fields, which contain information about taint flows and argument
// flows respectively.
type stateTracker struct {
	taintInfo   *FlowInformation                             // the taint information for the analysis
	cache       *analysis.Cache                              // the analysis cache containing pointer information, callgraph, ...
	changeFlag  bool                                         // a flag to keep track of changes in the analysis state
	blocksSeen  map[*ssa.BasicBlock]bool                     // a map to keep track of blocks seen during the analysis
	errors      map[ssa.Node]error                           // we don't panic during the analysis, but accumulate errors
	summary     *SummaryGraph                                // summary is the function summary currently being built
	deferStacks analysis.DeferResults                        // information about the possible defer stacks at RunDefers
	instrPaths  map[ssa.Instruction]map[ssa.Instruction]bool // instrPaths[i][j] means there is a path from i to j
}

// SingleFunctionResult holds the results of the intra-procedural analysis.
type SingleFunctionResult struct {
	IntraPaths map[ssa.Instruction]map[ssa.Instruction]bool // IntraPaths are the intra-procedural paths from sources
	// to sinks. This might disappear as the inter-procedural analysis should subsume it, but it is kept for now as
	// the user has the option to turn off the inter-procedural pass in the analysis.
	Summary *SummaryGraph // Summary is the procedure summary built by the analysis
}

// singleFunctionAnalysis is the main entry point of the intra procedural analysis.
func singleFunctionAnalysis(cache *analysis.Cache, function *ssa.Function, runit bool) (SingleFunctionResult, error) {
	sm := NewSummaryGraph(function, cache.PointerAnalysis.CallGraph.Nodes[function])
	tt := NewFlowInfo(cache.Config)
	tracker := &stateTracker{
		taintInfo:   tt,
		cache:       cache,
		changeFlag:  true,
		blocksSeen:  map[*ssa.BasicBlock]bool{},
		errors:      map[ssa.Node]error{},
		summary:     sm,
		deferStacks: analysis.AnalyzeFunctionDefers(function, false),
		instrPaths:  map[ssa.Instruction]map[ssa.Instruction]bool{},
	}

	// Output warning if defer stack is unbounded
	if !tracker.deferStacks.DeferStackBounded {
		err := cache.Logger.Output(2, fmt.Sprintf("Warning: defer stack unbounded in %s: %s",
			function.String(), analysis.Yellow("analysis unsound!")))
		if err != nil {
			return SingleFunctionResult{}, err
		}
	}

	// The parameters of the function are marked as Parameter
	for _, param := range function.Params {
		tt.AddSource(param, NewSource(param, Parameter, "*"))
	}

	// The free variables of the function are marked
	for _, fv := range function.FreeVars {
		tt.AddSource(fv, NewSource(fv, FreeVar, "*"))
	}

	// Run the analysis. Once the analysis terminates, mark the summary as constructed.
	if runit {
		ssafuncs.RunForwardIterative(tracker, function)
		sm.constructed = true
	}

	// If we have errors, return one (TODO: we'll decide how to handle them later)
	for _, err := range tracker.errors {
		return SingleFunctionResult{}, fmt.Errorf("error in intraprocedural analysis: %w", err)
	}
	return SingleFunctionResult{IntraPaths: tt.SinkSources, Summary: sm}, nil
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
		if path == "*" || source.RegionPath == path || source.RegionPath == "*" || source.RegionPath == "" {
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
	if ptr, ptrExists := t.cache.PointerAnalysis.Queries[x]; ptrExists {
		return &ptr
	}
	// Check indirect queries
	if ptr, ptrExists := t.cache.PointerAnalysis.IndirectQueries[x]; ptrExists {
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

// freeVarAliases returns the list of free variables of the function the value x aliases to.
// TODO: cache some of the information obtained by this query
func (t *stateTracker) freeVarAliases(x ssa.Value) []ssa.Value {
	var aliasedFv []ssa.Value
	for _, fv := range t.summary.parent.FreeVars {
		if x == fv {
			aliasedFv = append(aliasedFv, fv)
		} else {
			fvPtr := t.getAnyPointer(fv)
			xPtr := t.getAnyPointer(x)
			if fvPtr != nil && xPtr != nil && fvPtr.PointsTo().Intersects(xPtr.PointsTo()) {
				aliasedFv = append(aliasedFv, fv)
			}
		}
	}
	return aliasedFv
}

// checkCopyIntoArgs checks whether the source in is copying or writing into a value that aliases with
// one of the function's parameters. This keeps tracks of data flows to the function parameters that a
// caller might see.
func (t *stateTracker) checkCopyIntoArgs(in Source, out ssa.Value) {
	for _, aliasedParam := range t.paramAliases(out) {
		t.summary.addParamEdge(in, aliasedParam.(ssa.Node)) // type conversion is safe
	}
	for _, aliasedFreeVar := range t.freeVarAliases(out) {
		t.summary.addFreeVarEdge(in, aliasedFreeVar.(ssa.Node)) // type conversion is safe
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
	if ptr, ptrExists := t.cache.PointerAnalysis.Queries[v]; ptrExists {
		t.markAllAliases(source, ptr.PointsTo())
	}
	// By indirect query
	if ptr, ptrExists := t.cache.PointerAnalysis.IndirectQueries[v]; ptrExists {
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
		if t.checkFlow(source, sink, nil) {
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

// addClosureNode adds a closure node to the graph, and all the related sources and edges.
// The closure value is tracked like any other value.
func (t *stateTracker) addClosureNode(x *ssa.MakeClosure) {
	t.summary.addClosure(x)
	t.markValue(x, NewSource(x, Closure, ""))
	for _, boundVar := range x.Bindings {
		t.markValue(boundVar, NewQualifierSource(x, boundVar, BoundVar, ""))

		for _, origin := range t.getMarkedValueOrigins(boundVar, "*") {
			t.summary.addBoundVarEdge(origin, x, boundVar)

			for _, y := range t.paramAliases(boundVar) {
				t.summary.addParamEdge(origin, y.(ssa.Node))
			}
			for _, y := range t.freeVarAliases(boundVar) {
				t.summary.addFreeVarEdge(origin, y.(ssa.Node))
			}
		}
	}
	t.markValue(x, NewSource(x, Closure, "*"))
}

func (t *stateTracker) optionalSyntheticNode(asValue ssa.Value, asInstr ssa.Instruction, asNode ssa.Node) {
	if isSourceNode(t.cache.Config, asNode) {
		s := NewSource(asNode, Synthetic+TaintedVal, "")
		t.summary.addSyntheticNode(asInstr, "source")
		t.markValue(asValue, s)
	}
}

// callCommonTaint can be used for Call, Defer and Go that wrap a CallCommon.
func (t *stateTracker) callCommonTaint(callValue ssa.Value, callInstr ssa.CallInstruction, callCommon *ssa.CallCommon) {
	// Special cases
	if t.doBuiltinCall(callValue, callCommon, callInstr) {
		return
	}
	// Add call instruction to summary, in case it hasn't been added through callgraph
	t.summary.addCallInstr(t.cache, callInstr)
	// Check if node is source according to config
	sourceType := CallReturn
	if isSourceNode(t.taintInfo.config, callInstr.(ssa.Node)) { // type cast cannot fail
		sourceType += TaintedVal
	}
	// Mark call
	t.markValue(callValue, NewSource(callInstr.(ssa.Node), sourceType, ""))

	callIsSink := isSinkNode(t.taintInfo.config, callInstr.(ssa.Node))

	args := ssafuncs.GetArgs(callInstr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Mark call argument
		t.markValue(arg, NewQualifierSource(callInstr.(ssa.Node), arg, CallSiteArg, ""))

		for _, source := range t.getMarkedValueOrigins(arg, "*") {

			if source.IsTainted() && !source.IsSynthetic() {
				if callIsSink {
					// This is an intra-procedural path from a source to a sink
					t.AddFlowToSink(source, callInstr)
				}
			}
			// Add any necessary edge in the summary flow graph (incoming edges at call site)
			if t.checkFlow(source, callInstr, arg) {
				t.summary.addCallArgEdge(source, callInstr, arg)
				for _, x := range t.paramAliases(arg) {
					t.summary.addParamEdge(source, x.(ssa.Node))
				}
				for _, y := range t.freeVarAliases(arg) {
					t.summary.addFreeVarEdge(source, y.(ssa.Node))
				}
			}
		}
	}
}

func (t *stateTracker) checkFlow(source Source, dest ssa.Instruction, val ssa.Value) bool {
	sourceInstr, ok := source.Node.(ssa.Instruction)
	if !ok {
		return true
	}
	if val != nil {
		_, ok := dest.(*ssa.Defer)
		// For defers, we check reachability depending on the value type (reference of value)
		if ok {
			if _, isPtr := val.Type().Underlying().(*types.Pointer); isPtr {
				return true
			} else {
				return t.checkPathBetweenInstrs(sourceInstr, dest)
			}
		}
	}
	return t.checkPathBetweenInstrs(sourceInstr, dest)
}

func (t *stateTracker) checkPathBetweenInstrs(source ssa.Instruction, dest ssa.Instruction) bool {
	if reachableSet, ok := t.instrPaths[source]; ok {
		if reachesDest, ok := reachableSet[dest]; ok {
			return reachesDest
		} else {
			b := IntraProceduralPathExists(source, dest)
			t.instrPaths[source][dest] = b
			return b
		}
	} else {
		b := IntraProceduralPathExists(source, dest)
		t.instrPaths[source] = map[ssa.Instruction]bool{dest: b}
		return b
	}
}

// doBuiltinCall returns true if the call is a builtin that is handled by default, otherwise false.
// If true is returned, the analysis may ignore the call instruction.
func (t *stateTracker) doBuiltinCall(callValue ssa.Value, callCommon *ssa.CallCommon,
	instruction ssa.CallInstruction) bool {
	if callCommon.Value != nil {
		switch callCommon.Value.Name() {
		// for append, copy we simply propagate the taint like in a binary operator
		case "append", "copy", "ssa:wrapnilchk":
			for _, arg := range callCommon.Args {
				simpleTransitiveMarkPropagation(t, arg, callValue)
			}
			return true

		// for len, we also propagate the taint. This may not be necessary
		case "len":
			for _, arg := range callCommon.Args {
				simpleTransitiveMarkPropagation(t, arg, callValue)
			}
			return true

		// for close, delete, nothing is propagated
		case "close", "delete":
			return true

		// the builtin println doesn't return anything
		case "println":
			return true

		// for recover, we will need some form of panic analysis
		case "recover":
			fmt.Fprintf(os.Stderr, "Encountered recover at %s, the analysis may be unsound.\n",
				instruction.Parent().Prog.Fset.Position(instruction.Pos()))
			return true
		default:
			// Special case: the call to Error() of the builtin error interface
			// TODO: double check
			if callCommon.IsInvoke() &&
				callCommon.Method.Name() == "Error" &&
				len(callCommon.Args) == 0 {
				simpleTransitiveMarkPropagation(t, callCommon.Value, callValue)
				return true
			} else {
				return false
			}
		}
	} else {
		return false
	}
}

func (t *stateTracker) getInstr(blockNum int, instrNum int) (ssa.Instruction, error) {
	block := t.summary.parent.Blocks[blockNum]
	if block == nil {
		return nil, fmt.Errorf("invalid block")
	}
	instr := block.Instrs[instrNum]
	if instr == nil {
		return nil, fmt.Errorf("invalid instr")
	}
	return instr, nil
}

// doDefersStackSimulation fetches the possible defers stacks from the analysis and runs the analysis as if those
// calls happened in order that the RunDefers location
func (t *stateTracker) doDefersStackSimulation(r *ssa.RunDefers) error {
	stackSet := t.deferStacks.RunDeferSets[r]
	for _, stack := range stackSet {
		// Simulate a new block
		t.NewBlock(r.Block())
		for _, instrIndex := range stack {
			instr, err := t.getInstr(instrIndex.Block, instrIndex.Ins)
			if err != nil {
				return err
			}
			if d, ok := instr.(*ssa.Defer); ok {
				t.callCommonTaint(d.Value(), d, d.Common())
			} else {
				return fmt.Errorf("defer stacks should only contain defers")
			}
		}
	}
	return nil
}
