package dataflow

import (
	"fmt"
	"go/token"
	"go/types"

	"github.com/awslabs/argot/analysis/astfuncs"
	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/defers"
	"github.com/awslabs/argot/analysis/format"
	"github.com/awslabs/argot/analysis/functional"
	"github.com/awslabs/argot/analysis/ssafuncs"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// This file implements the single function analysis. This analysis pass inspects a single function and constructs:
// - a dataflow summary of the function
// This file `single_function.go` contains all the logic of the analysis and the transfer functions
// called to handle each instruction.
// The `single_function_instruction_ops.go` file contains all the functions that define how instructions in the function
// are handled.

// FlowInformation contains the dataflow information necessary for the analysis and function summary building.
type FlowInformation struct {
	Config         *config.Config              // user provided configuration identifying sources and sinks
	MarkedValues   map[ssa.Value]map[Mark]bool // map from values to the set of sources that mark them
	MarkedPointers map[*pointer.Pointer]Mark   // map from pointer sets to the sources that mark them
}

// NewFlowInfo returns a new FlowInformation with all maps initialized.
func NewFlowInfo(cfg *config.Config) *FlowInformation {
	return &FlowInformation{
		Config:         cfg,
		MarkedValues:   make(map[ssa.Value]map[Mark]bool),
		MarkedPointers: make(map[*pointer.Pointer]Mark),
	}
}

func (t *FlowInformation) HasMark(v ssa.Value, s Mark) bool {
	marks, ok := t.MarkedValues[v]
	return ok && marks[s]
}

// AddMark adds a mark to the tracking info structure and returns a boolean
// if new information has been inserted.
func (t *FlowInformation) AddMark(v ssa.Value, s Mark) bool {
	if vMarks, ok := t.MarkedValues[v]; ok {
		if vMarks[s] {
			return false
		} else {
			vMarks[s] = true
			return true
		}
	} else {
		t.MarkedValues[v] = map[Mark]bool{s: true}
		return true
	}
}

// stateTracker contains the information used by the intra-procedural dataflow analysis. The main components modified by
// the analysis  are the flowInfo and the argFlows fields, which contain information about taint flows and argument
// flows respectively.
type stateTracker struct {
	flowInfo       *FlowInformation                             // the data flow information for the analysis
	cache          *Cache                                       // the analysis cache containing pointer information, callgraph, ...
	changeFlag     bool                                         // a flag to keep track of changes in the analysis state
	blocksSeen     map[*ssa.BasicBlock]bool                     // a map to keep track of blocks seen during the analysis
	errors         map[ssa.Node]error                           // we don't panic during the analysis, but accumulate errors
	summary        *SummaryGraph                                // summary is the function summary currently being built
	deferStacks    defers.Results                               // information about the possible defer stacks at RunDefers
	instrPaths     map[ssa.Instruction]map[ssa.Instruction]bool // instrPaths[i][j] means there is a path from i to j
	paramAliases   map[ssa.Value]map[*ssa.Parameter]bool        // a map from values in the function to the parameter it aliases
	freeVarAliases map[ssa.Value]map[*ssa.FreeVar]bool          // a map from values to the free variable it aliases
	shouldTrack    func(*config.Config, ssa.Node) bool          // function that returns true if dataflow from the node should be tracked
}

// SingleFunctionResult holds the results of the intra-procedural analysis.
type SingleFunctionResult struct {
	Summary *SummaryGraph // Summary is the procedure summary built by the analysis
}

// SingleFunctionAnalysis is the main entry point of the intra procedural analysis.
func SingleFunctionAnalysis(cache *Cache, function *ssa.Function, runit bool,
	shouldTrack func(*config.Config, ssa.Node) bool) (SingleFunctionResult, error) {
	sm := NewSummaryGraph(function)
	flowInfo := NewFlowInfo(cache.Config)
	tracker := &stateTracker{
		flowInfo:       flowInfo,
		cache:          cache,
		changeFlag:     true,
		blocksSeen:     map[*ssa.BasicBlock]bool{},
		errors:         map[ssa.Node]error{},
		summary:        sm,
		deferStacks:    defers.AnalyzeFunction(function, false),
		instrPaths:     map[ssa.Instruction]map[ssa.Instruction]bool{},
		paramAliases:   map[ssa.Value]map[*ssa.Parameter]bool{},
		freeVarAliases: map[ssa.Value]map[*ssa.FreeVar]bool{},
		shouldTrack:    shouldTrack,
	}

	// Output warning if defer stack is unbounded
	if !tracker.deferStacks.DeferStackBounded {
		err := cache.Logger.Output(2, fmt.Sprintf("Warning: defer stack unbounded in %s: %s",
			function.String(), format.Yellow("analysis unsound!")))
		if err != nil {
			return SingleFunctionResult{}, err
		}
	}

	// Initialize alias maps
	ssafuncs.IterateValues(function, func(_ int, v ssa.Value) {
		tracker.paramAliases[v] = map[*ssa.Parameter]bool{}
		tracker.freeVarAliases[v] = map[*ssa.FreeVar]bool{}
	})

	// The parameters of the function are marked as Parameter
	for _, param := range function.Params {
		flowInfo.AddMark(param, NewMark(param, Parameter, "*"))
		tracker.addParamAliases(param)
	}
	// The free variables of the function are marked
	for _, fv := range function.FreeVars {
		flowInfo.AddMark(fv, NewMark(fv, FreeVar, "*"))
		tracker.addFreeVarAliases(fv)
	}

	// Special cases: load instructions in closures
	ssafuncs.IterateInstructions(function,
		func(_ int, i ssa.Instruction) {
			if load, ok := i.(*ssa.UnOp); ok && load.Op == token.MUL {
				for _, fv := range function.FreeVars {
					if fv == load.X {
						tracker.freeVarAliases[load][fv] = true
					}
				}
			}
		})

	// Collect global variable uses
	ssafuncs.IterateInstructions(function,
		func(_ int, i ssa.Instruction) {
			var operands []*ssa.Value
			operands = i.Operands(operands)
			for _, operand := range operands {
				// Add marks for globals
				if glob, ok := (*operand).(*ssa.Global); ok {
					if node, ok := cache.Globals[glob]; ok {
						tracker.summary.AddAccessGlobalNode(i, node)
					}
				}
			}
		})

	// Run the analysis. Once the analysis terminates, mark the summary as constructed.
	if runit {
		ssafuncs.RunForwardIterative(tracker, function)
		sm.SyncGlobals()
		sm.Constructed = true
	}

	// If we have errors, return one (TODO: we'll decide how to handle them later)
	for _, err := range tracker.errors {
		return SingleFunctionResult{}, fmt.Errorf("error in intraprocedural analysis: %w", err)
	}
	return SingleFunctionResult{Summary: sm}, nil
}

// getMarkedValueOrigins returns a mark and true if v is a marked value, otherwise it returns (nil, false)
// Uses both the direct taint information in the taint tracking info, and the pointer taint information, i.e:
// - A value is marked if it is directly marked
// - A value is marked if it is a pointer and some alias is marked.
// The path parameter enables path-sensitivity. If path is "*", any path is accepted and the analysis
// over-approximates.
func (t *stateTracker) getMarkedValueOrigins(v ssa.Value, path string) []Mark {
	var origins []Mark
	// when the value is directly marked as tainted.
	for mark := range t.flowInfo.MarkedValues[v] {
		if path == "*" || mark.RegionPath == path || mark.RegionPath == "*" || mark.RegionPath == "" {
			origins = append(origins, mark)
		}
	}

	// when the value's aliases is marked by intersecting with another marked values aliases
	if ptr := t.getPointer(v); ptr != nil {
		for other, mark := range t.flowInfo.MarkedPointers {
			if ptr.MayAlias(*other) {
				t.markValue(v, mark)
				origins = append(origins, mark)
			}
		}
	}
	return origins
}

// getAnyPointer returns the pointer to x according to the pointer analysis
func (t *stateTracker) getPointer(x ssa.Value) *pointer.Pointer {
	if ptr, ptrExists := t.cache.PointerAnalysis.Queries[x]; ptrExists {
		return &ptr
	}
	return nil
}

// getAnyPointer returns the pointer to x according to the pointer analysis
func (t *stateTracker) getIndirectPointer(x ssa.Value) *pointer.Pointer {
	// Check indirect queries
	if ptr, ptrExists := t.cache.PointerAnalysis.IndirectQueries[x]; ptrExists {
		return &ptr
	}
	return nil
}

// addParamAliases collects information about the value-aliases of the parameters
func (t *stateTracker) addParamAliases(x *ssa.Parameter) {
	t.paramAliases[x][x] = true
	addAliases(x, t.summary.Parent, t.getPointer(x), t.paramAliases, t.getPointer, t.getIndirectPointer)
	addAliases(x, t.summary.Parent, t.getIndirectPointer(x), t.paramAliases, t.getPointer, t.getIndirectPointer)
}

// addFreeVarAliases collects information about the value-aliases of the free variables
func (t *stateTracker) addFreeVarAliases(x *ssa.FreeVar) {
	t.freeVarAliases[x][x] = true
	addAliases(x, t.summary.Parent, t.getPointer(x), t.freeVarAliases, t.getPointer, t.getIndirectPointer)
	addAliases(x, t.summary.Parent, t.getIndirectPointer(x), t.freeVarAliases, t.getPointer, t.getIndirectPointer)
}

// checkCopyIntoArgs checks whether the mark in is copying or writing into a value that aliases with
// one of the function's parameters. This keeps tracks of data flows to the function parameters that a
// caller might see.
func (t *stateTracker) checkCopyIntoArgs(in Mark, out ssa.Value) {
	if astfuncs.IsNillableType(out.Type()) {
		for aliasedParam := range t.paramAliases[out] {
			t.summary.AddParamEdge(in, aliasedParam)
		}
		for aliasedFreeVar := range t.freeVarAliases[out] {
			t.summary.AddFreeVarEdge(in, aliasedFreeVar)
		}
	}
}

// checkFlowIntoGlobal checks whether the origin is data flowing into a global variable
func (t *stateTracker) checkFlowIntoGlobal(loc ssa.Instruction, origin Mark, out ssa.Value) {
	if glob, isGlob := out.(*ssa.Global); isGlob {
		t.summary.AddGlobalEdge(origin, loc, glob)
	}
}

// markAllAliases marks all the aliases of the pointer set using mark.
func (t *stateTracker) markAllAliases(mark Mark, ptr *pointer.Pointer) {
	if ptr == nil {
		return
	}
	// Look at every value in the points-to set.
	for _, label := range ptr.PointsTo().Labels() {
		if label != nil && label.Value() != nil {
			mark.RegionPath = label.Path()
			t.flowInfo.AddMark(label.Value(), mark)
		}
	}
	t.flowInfo.MarkedPointers[ptr] = mark
}

// markValue marks the value v and all values that propagate from v.
// If the value was not marked, it changes the changeFlag to true to indicate
// that the mark information has changed for the current pass.
func (t *stateTracker) markValue(v ssa.Value, mark Mark) {
	if t.flowInfo.HasMark(v, mark) {
		return
	}
	// v was not marked before
	t.changeFlag = t.flowInfo.AddMark(v, mark)
	// Propagate to any other value that is an alias of v
	// By direct query
	if ptr, ptrExists := t.cache.PointerAnalysis.Queries[v]; ptrExists {
		t.markAllAliases(mark, &ptr)
	}
	// By indirect query
	if ptr, ptrExists := t.cache.PointerAnalysis.IndirectQueries[v]; ptrExists {
		t.markAllAliases(mark, &ptr)
	}

	// SPECIAL CASE: value is result of make any <- v', mark v'
	// handles cases where a function f(_ any...) is called on some argument of concrete type
	if miVal, isMakeInterface := v.(*ssa.MakeInterface); isMakeInterface {
		// conversion to any or interface{}
		typStr := miVal.Type().String()
		if typStr == "any" || typStr == "interface{}" {
			t.markValue(miVal.X, mark)
		}
	}
}

// Helpers for propagating data flow

// simpleTransitiveMarkPropagation  propagates all the marks from in to out
func simpleTransitiveMarkPropagation(t *stateTracker, loc ssa.Instruction, in ssa.Value, out ssa.Value) {
	pathSensitiveMarkPropagation(t, loc, in, out, "*")
}

// pathSensitiveMarkPropagation propagates all the marks from in to out with the object path string
func pathSensitiveMarkPropagation(t *stateTracker, loc ssa.Instruction, in ssa.Value, out ssa.Value, path string) {
	if glob, ok := in.(*ssa.Global); ok {
		t.markValue(out, NewQualifierMark(loc.(ssa.Node), glob, Global, "*"))
	}
	for _, origin := range t.getMarkedValueOrigins(in, path) {
		t.markValue(out, origin)
		t.checkCopyIntoArgs(origin, out)
		t.checkFlowIntoGlobal(loc, origin, out)
	}
}

// addClosureNode adds a closure node to the graph, and all the related sources and edges.
// The closure value is tracked like any other value.
func (t *stateTracker) addClosureNode(x *ssa.MakeClosure) {
	t.summary.AddClosure(x)
	t.markValue(x, NewMark(x, Closure, ""))
	for _, boundVar := range x.Bindings {
		mark := NewQualifierMark(x, boundVar, BoundVar, "")

		t.markValue(boundVar, mark)

		for y := range t.paramAliases[boundVar] {
			t.summary.AddParamEdge(mark, y)
		}

		for y := range t.freeVarAliases[boundVar] {
			t.summary.AddFreeVarEdge(mark, y)
		}

		for _, origin := range t.getMarkedValueOrigins(boundVar, "*") {
			t.summary.AddBoundVarEdge(origin, x, boundVar)
		}
	}
	t.markValue(x, NewMark(x, Closure, "*"))
}

// optionalSyntheticNode tracks the flow of data from a synthetic node.
func (t *stateTracker) optionalSyntheticNode(asValue ssa.Value, asInstr ssa.Instruction, asNode ssa.Node) {
	if t.shouldTrack(t.cache.Config, asNode) {
		s := NewMark(asNode, Synthetic+TaintedVal, "")
		t.summary.AddSyntheticNode(asInstr, "source")
		t.markValue(asValue, s)
	}

	for _, origin := range t.getMarkedValueOrigins(asValue, "*") {
		_, isField := asInstr.(*ssa.Field)
		_, isFieldAddr := asInstr.(*ssa.FieldAddr)
		// check flow to avoid duplicate edges between synthetic nodes
		if (isField || isFieldAddr) && t.checkFlow(origin, asInstr, asValue) {
			t.summary.AddSyntheticNodeEdge(origin, asInstr, "*")
		}
	}
}

// callCommonTaint can be used for Call and Go instructions that wrap a CallCommon.
func (t *stateTracker) callCommonTaint(callValue ssa.Value, callInstr ssa.CallInstruction, callCommon *ssa.CallCommon) {
	// Special cases
	if t.doBuiltinCall(callValue, callCommon, callInstr) {
		return
	}

	// Add call instruction to summary, in case it hasn't been added through callgraph
	t.summary.AddCallInstr(t.cache, callInstr)
	// If a closure is being called: the closure value flows to the callsite
	if callInstr.Common().Method == nil {
		for _, mark := range t.getMarkedValueOrigins(callInstr.Common().Value, "*") {
			t.summary.AddCallNodeEdge(mark, callInstr)
		}
	}

	// Check if node is source according to config
	markType := CallReturn
	if t.shouldTrack(t.flowInfo.Config, callInstr.(ssa.Node)) { // type cast cannot fail
		markType += TaintedVal
	}
	// Mark call
	t.markValue(callValue, NewMark(callInstr.(ssa.Node), markType, ""))

	args := ssafuncs.GetArgs(callInstr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Mark call argument
		t.markValue(arg, NewQualifierMark(callInstr.(ssa.Node), arg, CallSiteArg, ""))
		// Special case: a global is received directly as an argument
		if _, ok := arg.(*ssa.Global); ok {
			tmpSrc := NewQualifierMark(callInstr.(ssa.Node), arg, Global, "")
			t.summary.AddCallArgEdge(tmpSrc, callInstr, arg)
		}

		for _, mark := range t.getMarkedValueOrigins(arg, "*") {
			// Add any necessary edge in the summary flow graph (incoming edges at call site)
			if t.checkFlow(mark, callInstr, arg) {
				t.summary.AddCallArgEdge(mark, callInstr, arg)
				// Add edges to parameters if the call may modify caller's arguments
				for x := range t.paramAliases[arg] {
					if astfuncs.IsNillableType(x.Type()) {
						t.summary.AddParamEdge(mark, x)
					}
				}
				for y := range t.freeVarAliases[arg] {
					if astfuncs.IsNillableType(y.Type()) {
						t.summary.AddFreeVarEdge(mark, y)
					}
				}
			}
		}
	}
}

// checkFlow checks whether there can be a flow between the source and the dest instruction. The destination must be
// and instruction. destVal can be used to specify that the flow is to the destination (the location) through
// a specific value. For example, destVal can be the argument of a function call.
func (t *stateTracker) checkFlow(source Mark, dest ssa.Instruction, destVal ssa.Value) bool {
	sourceInstr, ok := source.Node.(ssa.Instruction)
	if !ok {
		return true
	}

	if destVal == nil {
		return t.checkPathBetweenInstrs(sourceInstr, dest)
	}

	// If the destination instruction is a Defer and the destination value is a reference (pointer type) then the
	// taint will always flow to it, since the Defer will be executed after the source.
	if _, isDefer := dest.(*ssa.Defer); isDefer {
		if astfuncs.IsNillableType(destVal.Type()) {
			return true
		} else {
			return t.checkPathBetweenInstrs(sourceInstr, dest)
		}
	} else {
		if asVal, isVal := dest.(ssa.Value); isVal {
			// If the destination is a value of function type, then there is a flow when the source occurs before
			// any instruction that refers to the function (e.g. the function is returned, or called)
			// This is often the case when there is a flow through a closure that binds variables by reference, and
			// the variable is tainted after the closure is created.
			if _, isFunc := asVal.Type().Underlying().(*types.Signature); isFunc {
				return functional.Exists(*asVal.Referrers(),
					func(i ssa.Instruction) bool {
						return t.checkPathBetweenInstrs(sourceInstr, i)
					})
			}
		}
		return t.checkPathBetweenInstrs(sourceInstr, dest)
	}
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
		case "ssa:wrapnilchk":
			for _, arg := range callCommon.Args {
				simpleTransitiveMarkPropagation(t, instruction, arg, callValue)
			}
			return true
		case "append":
			if len(callCommon.Args) == 2 {
				sliceV := callCommon.Args[0]
				dataV := callCommon.Args[1]
				simpleTransitiveMarkPropagation(t, instruction, sliceV, callValue)
				simpleTransitiveMarkPropagation(t, instruction, dataV, callValue)
				return true
			} else {
				return false
			}

		case "copy":
			if len(callCommon.Args) == 2 {
				src := callCommon.Args[1]
				dst := callCommon.Args[0]
				simpleTransitiveMarkPropagation(t, instruction, src, dst)
				return true
			} else {
				return false
			}

		// for len, we also propagate the taint. This may not be necessary
		case "len":
			for _, arg := range callCommon.Args {
				simpleTransitiveMarkPropagation(t, instruction, arg, callValue)
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
			t.cache.Err.Printf("Encountered recover at %s, the analysis may be unsound.\n",
				instruction.Parent().Prog.Fset.Position(instruction.Pos()))
			return true
		default:
			// Special case: the call to Error() of the builtin error interface
			// TODO: double check
			if callCommon.IsInvoke() &&
				callCommon.Method.Name() == "Error" &&
				len(callCommon.Args) == 0 {
				simpleTransitiveMarkPropagation(t, instruction, callCommon.Value, callValue)
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
	block := t.summary.Parent.Blocks[blockNum]
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

// addAliases is a type parametric version of the alias caching functions
func addAliases[T comparable](x T, f *ssa.Function, ptr *pointer.Pointer, aliases map[ssa.Value]map[T]bool,
	oracleDirect func(value ssa.Value) *pointer.Pointer, oracleIndirect func(value ssa.Value) *pointer.Pointer) {
	if ptr != nil {
		for _, lb := range ptr.PointsTo().Labels() {
			if lb != nil && lb.Value() != nil && lb.Value().Parent() == f {
				aliases[lb.Value()][x] = true
			}
		}

		ssafuncs.IterateValues(f, func(_ int, v ssa.Value) {
			ptr2 := oracleIndirect(v)
			if ptr2 != nil && ptr.MayAlias(*ptr2) {
				aliases[v][x] = true
			}
			ptr3 := oracleDirect(v)
			if ptr3 != nil && ptr.MayAlias(*ptr3) {
				aliases[v][x] = true
			}
		})
	}
}
