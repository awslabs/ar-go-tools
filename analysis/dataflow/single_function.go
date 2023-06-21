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

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/colors"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// This file implements the single function analysis. This analysis pass inspects a single function and constructs
// a dataflow summary of the function.
// - this file `single_function.go` contains the logic that determines when to run the monotone framework analysis,
// call the monotone frameowrk analysis, and builds the dataflow graph from the result of the monotone framework
// analysis.
// - `single_function_monotone_analysis.go` contains all the functions relative to the monotone analysis part of this
// single function analysis.
// - `single_function_instruction_ops.go` file contains all the functions that define how instructions in the function
// are handled.

// SingleFunctionResult holds the results of the single-function analysis.
type SingleFunctionResult struct {
	Summary *SummaryGraph // Summary is the procedure summary built by the analysis
	Time    time.Duration // Time it took to compute the summary
}

// SingleFunctionAnalysis is the main entry point of the intra procedural analysis.
func SingleFunctionAnalysis(state *AnalyzerState, function *ssa.Function, buildSummary bool, id uint32,
	shouldTrack func(*config.Config, ssa.Node) bool,
	postBlockCallback func(*IntraAnalysisState)) (SingleFunctionResult, error) {
	sm := NewSummaryGraph(function, id)
	flowInfo := NewFlowInfo(state.Config, function)
	// The function should have at least one instruction!
	if len(function.Blocks) == 0 || len(function.Blocks[0].Instrs) == 0 {
		return SingleFunctionResult{Summary: sm}, nil
	}

	// Run the analysis. Once the analysis terminates, mark the summary as constructed.
	start := time.Now()
	if buildSummary {
		err := run(state, flowInfo, sm, shouldTrack, postBlockCallback)
		if err != nil {
			return SingleFunctionResult{Summary: sm, Time: time.Since(start)}, err
		}
	}

	return SingleFunctionResult{Summary: sm, Time: time.Since(start)}, nil
}

// run is the core of the single function analysis
func run(a *AnalyzerState, flowInfo *FlowInformation, sm *SummaryGraph,
	shouldTrack func(*config.Config, ssa.Node) bool,
	postBlockCallback func(*IntraAnalysisState)) error {
	state := &IntraAnalysisState{
		flowInfo:            flowInfo,
		parentAnalyzerState: a,
		changeFlag:          true,
		blocksSeen:          map[*ssa.BasicBlock]bool{},
		errors:              map[ssa.Node]error{},
		summary:             sm,
		deferStacks:         defers.AnalyzeFunction(sm.Parent, false),
		paths:               map[*ssa.BasicBlock]map[*ssa.BasicBlock]ConditionInfo{},
		instrPrev:           map[ssa.Instruction]map[ssa.Instruction]bool{},
		paramAliases:        map[ssa.Value]map[*ssa.Parameter]bool{},
		freeVarAliases:      map[ssa.Value]map[*ssa.FreeVar]bool{},
		shouldTrack:         shouldTrack,
		postBlockCallback:   postBlockCallback,
	}

	// Output warning if defer stack is unbounded
	if !state.deferStacks.DeferStackBounded {
		a.Logger.Warnf("Defer stack unbounded in %s: %s",
			sm.Parent.String(), colors.Yellow("analysis unsound!"))
	}
	// First, we initialize the state of the monotone framework analysis (see the initialize function for more details)
	state.initialize()
	// Once the state is initialized, we call the forward iterative monotone framework analysis. The algorithm is
	// defined generally in the lang package, but all the details, including transfer functions, are in the
	// single_function_monotone_analysis.go file
	lang.RunForwardIterative(state, sm.Parent)
	// Once the analysis has run, we have a state that maps each instruction to an abstract value at that instruction.
	// This abstract valuation maps values to the values that flow into them. This can directly be translated into
	// a dataflow graph, with special attention for closures.
	// Nest, we build the edges of the summary. The functions for edge building are in this file
	lang.IterateInstructions(sm.Parent, state.makeEdgesAtInstruction)
	// Synchronize the edges of global variables
	sm.SyncGlobals()
	// Mark the summary as constructed
	sm.Constructed = true
	// If we have errors, return one (TODO: we'll decide how to handle them later)
	for _, err := range state.errors {
		return fmt.Errorf("error in intraprocedural analysis: %w", err)
	}
	return nil
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
	}
	// Always check if it's a synthetic node
	state.makeEdgesSyntheticNodes(instr)
}

// makeEdgesAtCallsite generates all the edges specific to a given call site.
// Those are the edges to and from call arguments and to and from the call value.
func (state *IntraAnalysisState) makeEdgesAtCallSite(callInstr ssa.CallInstruction) {
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

	args := lang.GetArgs(callInstr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Special case: a global is received directly as an argument
		switch argInstr := arg.(type) {
		case *ssa.Global:
			tmpSrc := NewMark(callInstr.(ssa.Node), Global, "", argInstr, -1)
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
					if lang.IsNillableType(x.Type()) {
						state.summary.AddParamEdge(mark, x, nil)
					}
				}
				for y := range state.freeVarAliases[arg] {
					if lang.IsNillableType(y.Type()) {
						state.summary.AddFreeVarEdge(mark, y, nil)
					}
				}
			}
		}
	}
}

// updateBoundVarEdges updates the edges to bound variables.
func (state *IntraAnalysisState) updateBoundVarEdges(instr ssa.Instruction, x *ssa.MakeClosure) {
	for _, boundVar := range x.Bindings {
		for _, boundVarMark := range state.getMarkedValues(instr, boundVar, "*") {
			state.summary.AddBoundVarEdge(boundVarMark, x, boundVar, &ConditionInfo{Satisfiable: true})
		}
	}
}

// makeEdgesAtClosure adds all the edges corresponding the closure creation site: bound variable edges and any edge
// to parameters and free variables.
func (state *IntraAnalysisState) makeEdgesAtClosure(x *ssa.MakeClosure) {
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
func (state *IntraAnalysisState) makeEdgesAtReturn(x *ssa.Return) {
	for markedValue, marks := range state.flowInfo.MarkedValues[x] {
		switch val := markedValue.(type) {
		case *ssa.Call:
			// calling Type() may cause segmentation error
			break
		default:
			// Check the state of the analysis at the final return to see which parameters of free variables might
			// have been modified by the function
			for mark := range marks {
				if lang.IsNillableType(val.Type()) {
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

	for tupleIndex, result := range x.Results {
		switch r := result.(type) {
		case *ssa.MakeClosure:
			state.updateBoundVarEdges(x, r)
		}

		for _, origin := range state.getMarkedValues(x, result, "*") {
			state.summary.AddReturnEdge(origin, x, tupleIndex, nil)
		}
	}
}

// makeEdgesAtStoreInCapturedLabel creates edges for store instruction where the target is a pointer that is
// captured by a closure somewhere. The capture information is flow- and context insensitive, so the edge creation is
// too. The interprocedural information will be completed later.
func (state *IntraAnalysisState) makeEdgesAtStoreInCapturedLabel(x *ssa.Store) {
	bounds := state.isCapturedBy(x.Addr)
	if len(bounds) > 0 {
		for _, origin := range state.getMarkedValues(x, x.Addr, "*") {
			for _, label := range bounds {
				if label.Value() != nil {
					for target := range state.parentAnalyzerState.BoundingInfo[label.Value()] {
						state.summary.AddBoundLabelNode(x, label, *target)
						state.summary.AddBoundLabelNodeEdge(origin, x, nil)
					}
				}
			}
		}
	}
}

func (state *IntraAnalysisState) makeEdgesSyntheticNodes(instr ssa.Instruction) {
	if asValue, ok := instr.(ssa.Value); ok && state.shouldTrack(state.parentAnalyzerState.Config, instr.(ssa.Node)) {
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
//
// The destination must be an instruction. destVal can be used to specify that the flow is to the destination
// (the location) through a specific value. For example, destVal can be the argument of a function call.
//
// Note that in the flow-sensitive analysis, the condition returned should always be satisfiable, but we use the
// condition expressions to decorate edges and allow checking whether a flow is validated in the dataflow analysis.
// We should think of ways to accumulate conditions without using the checkFlow function, which was designed initially
// to filter the spurious flows of the flow-insensitive analysis.
func (state *IntraAnalysisState) checkFlow(source Mark, dest ssa.Instruction, destVal ssa.Value) ConditionInfo {
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
		if lang.IsNillableType(destVal.Type()) {
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
				return funcutil.FindMap(*asVal.Referrers(),
					func(i ssa.Instruction) ConditionInfo { return state.checkPathBetweenInstructions(sourceInstr, i) },
					func(c ConditionInfo) bool { return c.Satisfiable }).ValueOr(ConditionInfo{Satisfiable: false})
			}
		}
		return state.checkPathBetweenInstructions(sourceInstr, dest)
	}
}

func (state *IntraAnalysisState) checkPathBetweenInstructions(source ssa.Instruction, dest ssa.Instruction) ConditionInfo {
	var i, j int
	for k, instr := range source.Block().Instrs {
		if instr == source {
			i = k
		}
		if instr == dest {
			j = k
		}
	}
	if source.Block() == dest.Block() && i >= j {
		return NewImpossiblePath().Cond
	}
	if reachableSet, ok := state.paths[source.Block()]; ok {
		if c, ok := reachableSet[dest.Block()]; ok {
			return c
		} else {
			b := FindIntraProceduralPath(source, dest)
			state.paths[source.Block()][dest.Block()] = b.Cond
			return b.Cond
		}
	} else {
		b := FindIntraProceduralPath(source, dest)
		state.paths[source.Block()] = map[*ssa.BasicBlock]ConditionInfo{dest.Block(): b.Cond}
		return b.Cond
	}
}

// isCapturedBy checks the bounding analysis to query whether the value is captured by some closure, in which case an
// edge will need to be added
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
func ShouldBuildSummary(state *AnalyzerState, function *ssa.Function) bool {
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
	} else {
		// Check package summaries
		return !(summaries.PkgHasSummaries(pkg) || state.HasExternalContractSummary(function))
	}
}

// ShouldCreateSummary returns true if the function's summary should be *created during the single function analysis
// pass.
func ShouldCreateSummary(f *ssa.Function) bool {
	// if a summary is required, then this should evidently return true!
	if summaries.IsSummaryRequired(f) {
		return true
	}

	return summaries.IsUserDefinedFunction(f)
}
