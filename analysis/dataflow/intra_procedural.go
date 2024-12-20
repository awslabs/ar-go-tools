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
	"fmt"
	"go/types"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// This file implements the single function analysis. This analysis pass inspects a single function and constructs
// a dataflow summary of the function.
// - this file `single_function.go` contains the logic that determines when to run the monotone framework analysis,
// call the monotone framework analysis, and builds the dataflow graph from the result of the monotone framework
// analysis.
// - `single_function_monotone_analysis.go` contains all the functions relative to the monotone analysis part of this
// single function analysis.
// - `single_function_instruction_ops.go` file contains all the functions that define how instructions in the function
// are handled.

// IntraProceduralResult holds the results of the intra-procedural analysis.
type IntraProceduralResult struct {
	Summary *SummaryGraph // Summary is the procedure summary built by the analysis
	Time    time.Duration // Time it took to compute the summary
}

// IntraProceduralAnalysis is the main entry point of the intra procedural analysis.
func IntraProceduralAnalysis(state *State,
	function *ssa.Function,
	buildSummary bool,
	id uint32,
	shouldTrack func(*State, ssa.Node) bool,
	postBlockCallback func(*IntraAnalysisState)) (IntraProceduralResult, error) {
	var err error
	var sm *SummaryGraph
	existingSummary := state.FlowGraph.Summaries[function]

	if existingSummary == nil {
		sm = NewSummaryGraph(state, function, id, shouldTrack, postBlockCallback)
	} else {
		sm = existingSummary
		existingSummary.postBlockCallBack = postBlockCallback
		existingSummary.shouldTrack = shouldTrack
	}

	// The function should have at least one instruction!
	if len(function.Blocks) == 0 || len(function.Blocks[0].Instrs) == 0 {
		return IntraProceduralResult{Summary: sm}, nil
	}

	elapsed := time.Duration(0)
	// Run the analysis. Once the analysis terminates, mark the summary as constructed.
	if buildSummary {
		elapsed, err = RunIntraProcedural(state, sm)
		if err != nil {
			return IntraProceduralResult{Summary: sm, Time: elapsed}, err
		}
	}

	return IntraProceduralResult{Summary: sm, Time: elapsed}, nil
}

// RunIntraProcedural is the core of the intra-procedural analysis. It updates the summary graph *in place* using the
// information contained in the state. It is possible to create a graph first only using NewSummaryGraph and then
// run RunIntraProcedural to update the edges in the graph.
//
// RunIntraProcedural does not add any nodes except bound label nodes to the summary graph, it only updates information
// related to the edges.
func RunIntraProcedural(a *State, sm *SummaryGraph) (time.Duration, error) {
	if sm.Parent == nil {
		return time.Duration(0), fmt.Errorf("summary graph has no parent: %v", sm)
	}

	start := time.Now()
	flowInfo := NewFlowInfo(a.Config, sm.Parent)
	// This is the only place an IntraAnalysisState is initialized
	state := &IntraAnalysisState{
		flowInfo:            flowInfo,
		parentAnalyzerState: a,
		changeFlag:          true,
		blocksSeen:          make([]bool, flowInfo.NumBlocks),
		errors:              map[ssa.Node]error{},
		summary:             sm,
		deferStacks:         defers.AnalyzeFunction(sm.Parent, a.Logger),
		paths:               make([]*ConditionInfo, flowInfo.NumBlocks*flowInfo.NumBlocks),
		instrPrev:           make([]map[IndexT]bool, flowInfo.NumInstructions),
		paramAliases:        make([]map[*ssa.Parameter]bool, flowInfo.NumValues),
		freeVarAliases:      make([]map[*ssa.FreeVar]bool, flowInfo.NumValues),
		shouldTrack:         sm.shouldTrack,
		postBlockCallback:   sm.postBlockCallBack,
	}

	reportUnsoundFeatures(a, sm.Parent)

	// Output warning if defer stack is unbounded
	if !state.deferStacks.DeferStackBounded {
		a.Logger.Warnf("Defer stack unbounded in %s: %s",
			formatutil.Sanitize(sm.Parent.String()), formatutil.Yellow("analysis unsound!"))
	}
	// First, we initialize the state of the monotone framework analysis (see the initialize function for more details)
	state.initialize()
	// Once the state is initialized, we call the forward iterative monotone framework analysis. The algorithm is
	// defined generally in the lang package, but all the details, including transfer functions, are in the
	// single_function_monotone_analysis.go file
	lang.RunForwardIterative(state, sm.Parent)
	// Once the analysis has RunIntraProcedural, we have a state that maps each instruction to an abstract Value at
	// that instruction.  This abstract valuation maps values to the values that flow into them. This can directly be
	// translated into a dataflow graph, with special attention for closures.
	// Next, we build the edges of the summary. The functions for edge building are in this file
	lang.IterateInstructions(sm.Parent, state.makeEdgesAtInstruction)
	// Synchronize the edges of global variables
	sm.SyncGlobals()
	// Update the locsets / marks of the nodes. The locsets are elements that can be used to check results against
	// other analyses. Currently, the locsets are the set of instructions that the data represented by a given node
	// flows to.
	state.moveLocSetsToSummary()
	// Mark the summary as constructed
	sm.Constructed = true
	// If we have errors, return one. This is sufficient to warn the user that the results are incorrect.
	// TODO: manage error messages for better debugging
	for _, err := range state.errors {
		return time.Since(start), fmt.Errorf("error in intraprocedural analysis: %w", err)
	}
	return time.Since(start), nil
}

// Dataflow edges in the summary graph are added by the following functions. Those can be called after the iterative
// analysis has computed where all marks reach values at each instruction.

func (state *IntraAnalysisState) makeEdgesAtInstruction(_ int, instr ssa.Instruction) {
	switch typedInstr := instr.(type) {
	case ssa.CallInstruction:
		state.makeEdgesAtCallSite(typedInstr)
	case *ssa.MakeClosure:
		state.makeEdgesAtClosure(typedInstr)
	case *ssa.Return:
		state.makeEdgesAtReturn(typedInstr)
	case *ssa.Store:
		state.makeEdgesAtStoreInCapturedLabel(typedInstr)
	case *ssa.If:
		state.makeEdgesAtIf(typedInstr)
	}
	// Always check if it's a synthetic node
	state.makeEdgesSyntheticNodes(instr)
}

// makeEdgesAtCallsite generates all the edges specific to a given call site.
// Those are the edges to and from call arguments and to and from the call Value.
func (state *IntraAnalysisState) makeEdgesAtCallSite(callInstr ssa.CallInstruction) {
	if isHandledBuiltinCall(callInstr) {
		makeEdgesAtBuiltinCall(state, callInstr)
		return
	}
	// add call node edges for call instructions whose Value corresponds to a function (i.e. the Method is nil)
	if callInstr.Common().Method == nil {
		for _, mark := range state.getMarks(callInstr, callInstr.Common().Value, "", true) {
			state.summary.addCallEdge(mark, nil, callInstr)
			if closure, isMakeClosure := mark.Mark.Node.(*ssa.MakeClosure); isMakeClosure {
				state.updateBoundVarEdges(callInstr, closure)
			}
		}
	}

	args := lang.GetArgs(callInstr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Special case: a global is received directly as an argument
		switch argInstr := arg.(type) {
		case *ssa.Global:
			tmpSrc := state.flowInfo.GetNewMark(callInstr.(ssa.Node), Global, argInstr, NonIndexMark)
			state.summary.addCallArgEdge(MarkWithAccessPath{tmpSrc, ""}, nil, callInstr, argInstr)
		case *ssa.MakeClosure:
			state.updateBoundVarEdges(callInstr, argInstr)
		}
		marks := state.getMarks(callInstr, arg, "", false)
		for _, mark := range marks {
			// Add any necessary edge in the summary flow graph (incoming edges at call site)
			c := state.checkFlow(mark.Mark, callInstr, arg)
			if c.Satisfiable {
				var applicableCond *ConditionInfo
				if c2 := c.AsPredicateTo(arg); len(c2.Conditions) > 0 {
					applicableCond = &c2
				}
				// Add the condition only if it is a predicate on the argument, i.e. there are boolean functions
				// that apply to the destination Value
				state.summary.addCallArgEdge(mark, applicableCond, callInstr, arg)
				argId := state.flowInfo.ValueID[arg] // base argument value is guaranteed to be indexed
				// Add edges to parameters if the call may modify caller's arguments
				for x := range state.paramAliases[argId] {
					if lang.IsNillableType(x.Type()) {
						state.summary.addParamEdge(mark, applicableCond, x)
					}
				}
				for y := range state.freeVarAliases[argId] {
					if lang.IsNillableType(y.Type()) {
						state.summary.addFreeVarEdge(mark, applicableCond, y)
					}
				}
			}
		}
	}
}

// updateBoundVarEdges updates the edges to bound variables.
func (state *IntraAnalysisState) updateBoundVarEdges(instr ssa.Instruction, x *ssa.MakeClosure) {
	for _, boundVar := range x.Bindings {
		for _, boundVarMark := range state.getMarks(instr, boundVar, "", false) {
			state.summary.addBoundVarEdge(boundVarMark, &ConditionInfo{Satisfiable: true}, x, boundVar)
		}
	}
}

// makeEdgesAtClosure adds all the edges corresponding the closure creation site: bound variable edges and any edge
// to parameters and free variables.
func (state *IntraAnalysisState) makeEdgesAtClosure(x *ssa.MakeClosure) {
	for _, boundVar := range x.Bindings {
		for _, markWithPath := range state.getMarks(x, boundVar, "", false) {
			mark := markWithPath.Mark
			if mark.IsClosure() && mark.Node == x {
				continue // avoid spurious edges from closure to its own bound variables
			}
			state.summary.addBoundVarEdge(markWithPath, nil, x, boundVar)
			boundVarID, ok := state.flowInfo.GetValueID(boundVar)
			if !ok {
				continue
			}
			for y := range state.paramAliases[boundVarID] {
				state.summary.addParamEdge(markWithPath, nil, y)
			}

			for y := range state.freeVarAliases[boundVarID] {
				state.summary.addFreeVarEdge(markWithPath, nil, y)
			}
		}
	}
}

// makeEdgesAtReturn creates all the edges to the return node
func (state *IntraAnalysisState) makeEdgesAtReturn(x *ssa.Return) {
	n := state.flowInfo.NumValues
	iID := state.flowInfo.GetInstrPos(x)
	for _, abstractValue := range state.flowInfo.MarkedValues[iID : iID+n] {
		if abstractValue == nil {
			continue
		}
		markedValue := abstractValue.value
		switch val := markedValue.(type) {
		case *ssa.Call:
			// calling Type() may cause segmentation error
			break
		default:
			// Check the state of the analysis at the final return to see which parameters or free variables might
			// have been modified by the function
			if lang.IsNillableType(val.Type()) {
				for _, mark := range abstractValue.AllMarks() {
					markedValueID, ok := state.flowInfo.GetValueID(markedValue)
					if !ok {
						continue
					}
					for aliasedParam := range state.paramAliases[markedValueID] {
						state.summary.addParamEdge(mark, nil, aliasedParam)
					}
					for aliasedFreeVar := range state.freeVarAliases[markedValueID] {
						state.summary.addFreeVarEdge(mark, nil, aliasedFreeVar)
					}
				}
			}
		}
	}

	for tupleIndex, result := range x.Results {
		switch r := result.(type) {
		case *ssa.MakeClosure:
			state.updateBoundVarEdges(x, r)
		}

		for _, origin := range state.getMarks(x, result, "", true) {
			state.summary.addReturnEdge(origin, nil, x, tupleIndex)
		}
	}
}

// makeEdgesAtStoreInCapturedLabel creates edges for store instruction where the target is a pointer that is
// captured by a closure somewhere. The capture information is flow- and context insensitive, so the edge creation is
// too. The interprocedural information will be completed later.
func (state *IntraAnalysisState) makeEdgesAtStoreInCapturedLabel(x *ssa.Store) {
	bounds := state.isCapturedBy(x.Addr)
	if len(bounds) > 0 {
		for _, label := range bounds {
			for target := range state.parentAnalyzerState.BoundingInfo[label.Value()] {
				state.summary.addBoundLabelNode(x, label, *target)
			}
		}
		for _, origin := range state.getMarks(x, x.Addr, "", false) {
			state.summary.addBoundLabelEdge(origin, nil, x)
		}
	}
}

func (state *IntraAnalysisState) makeEdgesAtIf(x *ssa.If) {
	for _, origin := range state.getMarks(x, x.Cond, "", false) {
		state.summary.addIfEdge(origin, nil, x)
	}
}

// makeEdgesSyntheticNodes analyzes the synthetic
func (state *IntraAnalysisState) makeEdgesSyntheticNodes(instr ssa.Instruction) {
	aState := state.parentAnalyzerState
	if !state.shouldTrack(aState, instr.(ssa.Node)) {
		return
	}
	if asValue, ok := instr.(ssa.Value); ok {
		for _, origin := range state.getMarks(instr, asValue, "", false) {
			_, isField := instr.(*ssa.Field)
			_, isFieldAddr := instr.(*ssa.FieldAddr)
			// check flow to avoid duplicate edges between synthetic nodes
			if isField || isFieldAddr {
				state.summary.addSyntheticEdge(origin, nil, instr, "")
			}
		}
	} else if storeInstr, isStore := instr.(*ssa.Store); isStore {
		for _, origin := range state.getMarks(instr, storeInstr.Val, "", false) {
			state.summary.addSyntheticEdge(origin, nil, instr, "")
		}
	}
}

func (state *IntraAnalysisState) moveLocSetsToSummary() {
	for mark, locSet := range state.flowInfo.LocSet {
		for _, graphNode := range state.summary.selectNodesFromMark(*mark) {
			graphNode.SetLocs(locSet)
		}
	}
}

// checkFlow checks whether there can be a flow between the source and the targetInfo instruction and returns a
// condition c. If c.Satisfiable is false, there is no path. If it is true, then there may be a non-empty set of
// conditions in the Conditions list.
//
// The destination must be an instruction. destVal can be used to specify that the flow is to the destination
// (the location) through a specific value. For example, destVal can be the argument of a function call.
//
// Note that in the flow-sensitive analysis, the condition returned should always be satisfiable, but we use the
// condition expressions to decorate edges and allow checking whether a flow is validated in the dataflow analysis.
// We should think of ways to accumulate conditions without using the checkFlow function, which was designed initially
// to filter the spurious flows of the flow-insensitive analysis.
func (state *IntraAnalysisState) checkFlow(source *Mark, dest ssa.Instruction, destVal ssa.Value) ConditionInfo {
	sourceInstr, ok := source.Node.(ssa.Instruction)
	if !ok {
		// if destination is parameter or free variable, this check is not meant to do anything
		// (the flow to a parameter or free var is observed AFTER the function returns)
		_, isDestParam := destVal.(*ssa.Parameter)
		_, isDestFreeVar := destVal.(*ssa.Parameter)
		if !source.IsParameter() || len(dest.Parent().Blocks) <= 0 || isDestFreeVar || isDestParam {
			return ConditionInfo{Satisfiable: true}
		}
		sourceInstr = dest.Parent().Blocks[0].Instrs[0]
	}

	if destVal == nil {
		return state.checkPathBetweenInstructions(sourceInstr, dest)
	}

	// If the destination instruction is a Defer and the destination value is a reference (pointer type) then the
	// taint will always flow to it, since the Defer will be executed after the source.
	if _, isDefer := dest.(*ssa.Defer); isDefer {
		if lang.IsNillableType(destVal.Type()) {
			return ConditionInfo{Satisfiable: true}
		}
		return state.checkPathBetweenInstructions(sourceInstr, dest)
	}
	if asVal, isVal := dest.(ssa.Value); isVal {
		// If the destination is a value of function type, then there is a flow when the source occurs before
		// any instruction that refers to the function (e.g. the function is returned, or called)
		// This is often the case when there is a flow through a closure that binds variables by reference, and
		// the variable is tainted after the closure is created.
		if _, isFunc := asVal.Type().Underlying().(*types.Signature); isFunc {
			return funcutil.FindMap(*asVal.Referrers(),
				func(i ssa.Instruction) ConditionInfo { return state.checkPathBetweenInstructions(sourceInstr, i) },
				func(c ConditionInfo) bool { return c.Satisfiable }).ValueOr(ConditionInfo{Satisfiable: false})
		}
	}
	return state.checkPathBetweenInstructions(sourceInstr, dest)

}

func (state *IntraAnalysisState) checkPathBetweenInstructions(source ssa.Instruction,
	dest ssa.Instruction) ConditionInfo {
	var sourceIndex, destIndex int
	for k, instr := range source.Block().Instrs {
		if instr == source {
			sourceIndex = k
		}
		if instr == dest {
			destIndex = k
		}
	}

	if source.Block().Index == dest.Block().Index && sourceIndex < destIndex {
		n := newImpossiblePath()
		n.Cond.Satisfiable = true
		return ConditionInfo{Satisfiable: true}
	}

	pos := IndexT(source.Block().Index)*state.flowInfo.NumBlocks + IndexT(dest.Block().Index)
	if c := state.paths[pos]; c != nil {
		return *c
	}
	b := FindIntraProceduralPath(source, dest)
	state.paths[pos] = &b.Cond
	return b.Cond
}

// isCapturedBy checks the bounding analysis to query whether the value is captured by some closure, in which case an
// edge will need to be added
// Guarantees that all label values in the slice of pointer labels returned are non-nil.
func (state *IntraAnalysisState) isCapturedBy(value ssa.Value) []*pointer.Label {
	var maps []*pointer.Label
	if ptr, ok := state.parentAnalyzerState.PointerAnalysis.Queries[value]; ok {
		for _, label := range ptr.PointsTo().Labels() {
			if label.Value() == nil {
				continue
			}
			_, isBound := state.parentAnalyzerState.BoundingInfo[label.Value()]
			if isBound {
				maps = append(maps, label)
			}
		}
	}
	if ptr, ok := state.parentAnalyzerState.PointerAnalysis.IndirectQueries[value]; ok {
		for _, label := range ptr.PointsTo().Labels() {
			if label.Value() == nil {
				continue
			}
			_, isBound := state.parentAnalyzerState.BoundingInfo[label.Value()]
			if isBound {
				maps = append(maps, label)
			}
		}
	}
	return maps
}

// ShouldBuildSummary returns true if the function's summary should be *built* during the single function analysis
// pass. This is not necessary for functions that have summaries that are externally defined, for example.
//
// ShouldBuildSummary returns true when:
//   - the state, the function or the function's package is nil (nil function must be handled by summary builder)
//   - the function summary is always required, as specified by [summaries.IsSummaryRequired]
//   - summaries are not built on demand
//   - the function is not filtered out by the pkg-filter (i.e. the pkg-filter matches the function when present)
//   - the function is not already summarized by a predefined summary or has an external contract
func ShouldBuildSummary(state *State, function *ssa.Function) bool {
	if state.Config != nil && state.Config.SummarizeOnDemand {
		return false
	}

	if state == nil || function == nil || summaries.IsSummaryRequired(function) {
		return true
	}

	pkg := function.Package()
	if pkg == nil {
		return true
	}

	// Is PkgPrefix specified?
	if state.Config != nil && state.Config.PkgFilter != "" {
		pkgKey := pkg.Pkg.Path()
		return state.Config.MatchPkgFilter(pkgKey) || pkgKey == "command-line-arguments"
	}
	// Check package summaries
	return !(summaries.PkgHasSummaries(pkg) || state.HasExternalContractSummary(function))
}
