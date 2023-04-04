package dataflow

import (
	"fmt"
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

// SingleFunctionResult holds the results of the intra-procedural analysis.
type SingleFunctionResult struct {
	Summary         *SummaryGraph    // Summary is the procedure summary built by the analysis
	FlowInformation *FlowInformation // Flow information: the final state of the analysis
}

// SingleFunctionAnalysis is the main entry point of the intra procedural analysis.
func SingleFunctionAnalysis(cache *Cache, function *ssa.Function, runit bool, id uint32,
	shouldTrack func(*config.Config, ssa.Node) bool) (SingleFunctionResult, error) {
	sm := NewSummaryGraph(function, id)
	flowInfo := NewFlowInfo(cache.Config, function)
	state := &analysisState{
		flowInfo:       flowInfo,
		cache:          cache,
		changeFlag:     true,
		blocksSeen:     map[*ssa.BasicBlock]bool{},
		errors:         map[ssa.Node]error{},
		summary:        sm,
		deferStacks:    defers.AnalyzeFunction(function, false),
		instrPaths:     map[ssa.Instruction]map[ssa.Instruction]ConditionInfo{},
		instrPrev:      map[ssa.Instruction]map[ssa.Instruction]bool{},
		paramAliases:   map[ssa.Value]map[*ssa.Parameter]bool{},
		freeVarAliases: map[ssa.Value]map[*ssa.FreeVar]bool{},
		shouldTrack:    shouldTrack,
	}

	// The function should have at least one instruction!
	if len(function.Blocks) == 0 || len(function.Blocks[0].Instrs) == 0 {
		return SingleFunctionResult{Summary: sm}, nil
	}
	// Output warning if defer stack is unbounded
	if !state.deferStacks.DeferStackBounded {
		err := cache.Logger.Output(2, fmt.Sprintf("Warning: defer stack unbounded in %s: %s",
			function.String(), format.Yellow("analysis unsound!")))
		if err != nil {
			return SingleFunctionResult{}, err
		}
	}

	state.initialize()

	// Run the analysis. Once the analysis terminates, mark the summary as constructed.
	if runit {
		// Run the monotone framework analysis: populate the flowInfo. The functions for the analysis are in the
		// single_function_monotone_analysis.go file
		ssafuncs.RunForwardIterative(state, function)
		// Build the edges of the summary. The functions for edge building are in this file
		ssafuncs.IterateInstructions(function, state.makeEdgesAtInstruction)
		// Synchronize the edges of global variables
		sm.SyncGlobals()
		sm.Constructed = true
	}

	// If we have errors, return one (TODO: we'll decide how to handle them later)
	for _, err := range state.errors {
		return SingleFunctionResult{}, fmt.Errorf("error in intraprocedural analysis: %w", err)
	}
	return SingleFunctionResult{Summary: sm, FlowInformation: flowInfo}, nil
}

// Dataflow edges in the summary graph are added by the following functions. Those can be called after the iterative
// analysis has computed where all marks reach values at each instruction.

func (state *analysisState) makeEdgesAtInstruction(_ int, instr ssa.Instruction) {
	switch typedInstr := instr.(type) {
	case ssa.CallInstruction:
		state.makeEdgesAtCallSite(typedInstr)
	case *ssa.MakeClosure:
		state.makeEdgesAtClosure(typedInstr)
	case *ssa.Return:
		state.makeEdgesAtReturn(typedInstr)
	case *ssa.Store:
		state.makeEdgesAtStoreInCapturedLabel(typedInstr)
	}
	// Always check if it's a synthetic node
	state.makeEdgesSyntheticNodes(instr)
}

// makeEdgesAtCallsite generates all the edges specific to a given call site.
// Those are the edges to and from call arguments and to and from the call value.
func (state *analysisState) makeEdgesAtCallSite(callInstr ssa.CallInstruction) {
	if isHandledBuiltinCall(callInstr) {
		return
	}
	// add call node edges for call instructions whose value corresponds to a function (i.e. the Method is nil)
	if callInstr.Common().Method == nil {
		for _, mark := range state.getMarkedValues(callInstr, callInstr.Common().Value, "*") {
			state.summary.AddCallNodeEdge(mark, callInstr, nil)
			switch x := mark.Node.(type) {
			case *ssa.MakeClosure:
				state.updateBoundVarEdges(callInstr, x)
			}
		}
	}

	args := ssafuncs.GetArgs(callInstr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Special case: a global is received directly as an argument
		switch argInstr := arg.(type) {
		case *ssa.Global:
			tmpSrc := NewQualifierMark(callInstr.(ssa.Node), argInstr, Global, "")
			state.summary.AddCallArgEdge(tmpSrc, callInstr, argInstr, nil)
		case *ssa.MakeClosure:
			state.updateBoundVarEdges(callInstr, argInstr)
		}

		for _, mark := range state.getMarkedValues(callInstr, arg, "*") {
			// Add any necessary edge in the summary flow graph (incoming edges at call site)
			c := state.checkFlow(mark, callInstr, arg)
			if c.Satisfiable {
				// Add the condition only if it is a predicate on the argument, i.e. there are boolean functions
				// that apply to the destination value
				if c2 := c.AsPredicateTo(arg); len(c2.Conditions) > 0 {
					state.summary.AddCallArgEdge(mark, callInstr, arg, &c2)
				} else {
					state.summary.AddCallArgEdge(mark, callInstr, arg, nil)
				}
				// Add edges to parameters if the call may modify caller's arguments
				for x := range state.paramAliases[arg] {
					if astfuncs.IsNillableType(x.Type()) {
						state.summary.AddParamEdge(mark, x, nil)
					}
				}
				for y := range state.freeVarAliases[arg] {
					if astfuncs.IsNillableType(y.Type()) {
						state.summary.AddFreeVarEdge(mark, y, nil)
					}
				}
			}
		}
	}
}

// updateBoundVarEdges updates the edges to bound variables.
func (state *analysisState) updateBoundVarEdges(instr ssa.Instruction, x *ssa.MakeClosure) {
	for _, boundVar := range x.Bindings {
		for _, boundVarMark := range state.getMarkedValues(instr, boundVar, "*") {
			state.summary.AddBoundVarEdge(boundVarMark, x, boundVar, &ConditionInfo{Satisfiable: true})
		}
	}
}

// makeEdgesAtClosure adds all the edges corresponding the closure creation site: bound variable edges and any edge
// to parameters and free variables.
func (state *analysisState) makeEdgesAtClosure(x *ssa.MakeClosure) {
	for _, boundVar := range x.Bindings {
		for _, mark := range state.getMarkedValues(x, boundVar, "*") {
			state.summary.AddBoundVarEdge(mark, x, boundVar, nil)
			for y := range state.paramAliases[boundVar] {
				state.summary.AddParamEdge(mark, y, nil)
			}

			for y := range state.freeVarAliases[boundVar] {
				state.summary.AddFreeVarEdge(mark, y, nil)
			}
		}
	}
}

// makeEdgesAtReturn creates all the edges to the return node
func (state *analysisState) makeEdgesAtReturn(x *ssa.Return) {
	for markedValue, marks := range state.flowInfo.MarkedValues[x] {
		switch val := markedValue.(type) {
		case *ssa.Call:
			// calling Type() will cause segmentation error
			break
		default:
			// Check the state of the analysis at the final return to see which parameters of free variables might
			// have been modified by the function
			for mark := range marks {
				if astfuncs.IsNillableType(val.Type()) {
					for aliasedParam := range state.paramAliases[markedValue] {
						state.summary.AddParamEdge(mark, aliasedParam, nil)
					}
					for aliasedFreeVar := range state.freeVarAliases[markedValue] {
						state.summary.AddFreeVarEdge(mark, aliasedFreeVar, nil)
					}
				}
			}
		}
	}

	for _, result := range x.Results {
		switch r := result.(type) {
		case *ssa.MakeClosure:
			state.updateBoundVarEdges(x, r)
		}
	}
}

// makeEdgesAtStoreInCapturedLabel creates edges for store instruction where the target is a pointer that is
// captured by a closure somewhere. The capture information is flow- and context insensitive, so the edge creation is
// too. The interprocedural information will be completed later.
func (state *analysisState) makeEdgesAtStoreInCapturedLabel(x *ssa.Store) {
	bounds := state.isCapturedBy(x.Addr)
	if len(bounds) > 0 {
		for _, origin := range state.getMarkedValues(x, x.Addr, "*") {
			for _, label := range bounds {
				if label.Value() != nil {
					for target := range state.cache.BoundingInfo[label.Value()] {
						state.summary.AddBoundLabelNode(x, label, *target)
						state.summary.AddBoundLabelNodeEdge(origin, x, nil)
					}
				}
			}
		}
	}
}

func (state *analysisState) makeEdgesSyntheticNodes(instr ssa.Instruction) {
	if asValue, ok := instr.(ssa.Value); ok && state.shouldTrack(state.cache.Config, instr.(ssa.Node)) {
		for _, origin := range state.getMarkedValues(instr, asValue, "*") {
			_, isField := instr.(*ssa.Field)
			_, isFieldAddr := instr.(*ssa.FieldAddr)
			// check flow to avoid duplicate edges between synthetic nodes
			if isField || isFieldAddr {
				state.summary.AddSyntheticNodeEdge(origin, instr, "*", nil)
			}
		}
	}
}

// checkFlow checks whether there can be a flow between the source and the targetInfo instruction and returns a
// condition c. If c.Satisfiable is false, there is no path. If it is true, then there may be a non-empty set of
// conditions in the Conditions list.
// The destination must be an instruction. destVal can be used to specify that the flow is to the destination
// (the location) through a specific value. For example, destVal can be the argument of a function call.
// Note that in the flow-sensitive analysis, the condition returned should always be satisfiable, but we use the
// condition expressions to decorate edges and allow checking whether a flow is validated in the dataflow analysis.
func (state *analysisState) checkFlow(source Mark, dest ssa.Instruction, destVal ssa.Value) ConditionInfo {
	sourceInstr, ok := source.Node.(ssa.Instruction)
	if !ok {
		return ConditionInfo{Satisfiable: true}
	}

	if destVal == nil {
		return state.checkPathBetweenInstructions(sourceInstr, dest)
	}

	// If the destination instruction is a Defer and the destination value is a reference (pointer type) then the
	// taint will always flow to it, since the Defer will be executed after the source.
	if _, isDefer := dest.(*ssa.Defer); isDefer {
		if astfuncs.IsNillableType(destVal.Type()) {
			return ConditionInfo{Satisfiable: true}
		} else {
			return state.checkPathBetweenInstructions(sourceInstr, dest)
		}
	} else {
		if asVal, isVal := dest.(ssa.Value); isVal {
			// If the destination is a value of function type, then there is a flow when the source occurs before
			// any instruction that refers to the function (e.g. the function is returned, or called)
			// This is often the case when there is a flow through a closure that binds variables by reference, and
			// the variable is tainted after the closure is created.
			if _, isFunc := asVal.Type().Underlying().(*types.Signature); isFunc {
				return functional.FindMap(*asVal.Referrers(),
					func(i ssa.Instruction) ConditionInfo { return state.checkPathBetweenInstructions(sourceInstr, i) },
					func(c ConditionInfo) bool { return c.Satisfiable }).ValueOr(ConditionInfo{Satisfiable: false})
			}
		}
		return state.checkPathBetweenInstructions(sourceInstr, dest)
	}
}

func (state *analysisState) checkPathBetweenInstructions(source ssa.Instruction, dest ssa.Instruction) ConditionInfo {
	if reachableSet, ok := state.instrPaths[source]; ok {
		if c, ok := reachableSet[dest]; ok {
			return c
		} else {
			b := FindIntraProceduralPath(source, dest)
			state.instrPaths[source][dest] = b.Cond
			return b.Cond
		}
	} else {
		b := FindIntraProceduralPath(source, dest)
		state.instrPaths[source] = map[ssa.Instruction]ConditionInfo{dest: b.Cond}
		return b.Cond
	}
}

// isCapturedBy checks the bounding analysis to query whether the value is captured by some closure, in which case an
// edge will need to be added
func (state *analysisState) isCapturedBy(value ssa.Value) []*pointer.Label {
	var maps []*pointer.Label
	if ptr, ok := state.cache.PointerAnalysis.Queries[value]; ok {
		for _, label := range ptr.PointsTo().Labels() {
			if label.Value() == nil {
				continue
			}
			_, isBound := state.cache.BoundingInfo[label.Value()]
			if isBound {
				maps = append(maps, label)
			}
		}
	}
	if ptr, ok := state.cache.PointerAnalysis.IndirectQueries[value]; ok {
		for _, label := range ptr.PointsTo().Labels() {
			if label.Value() == nil {
				continue
			}
			_, isBound := state.cache.BoundingInfo[label.Value()]
			if isBound {
				maps = append(maps, label)
			}
		}
	}
	return maps
}
