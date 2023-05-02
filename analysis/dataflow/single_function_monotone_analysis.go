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
	"go/token"

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/defers"
	"github.com/awslabs/argot/analysis/lang"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// AnalysisState contains the information used by the intra-procedural dataflow analysis. The main components modified by
// the analysis  are the flowInfo and the argFlows fields, which contain information about taint flows and argument
// flows respectively.
type AnalysisState struct {
	// the data flow information for the analysis
	flowInfo *FlowInformation

	// the analysis cache containing pointer information, callgraph, ...
	cache *Cache

	// changeFlag keeps track of changes in the analysis state and is reset each time a new block is visited
	changeFlag bool

	// curBlock keeps track of the curren block
	curBlock *ssa.BasicBlock

	// blocksSeen is a map to keep track of blocks seen during the analysis
	blocksSeen map[*ssa.BasicBlock]bool

	// errors stores the errors met during the analysis. We don't panic during the analysis, but accumulate errors and
	// the client is responsible for proper handling of the errors
	errors map[ssa.Node]error

	// summary is the function summary currently being built. The function being analyzed is the Parent of the summary.
	summary *SummaryGraph

	// deferStacks contains information about the possible defer stacks at RunDefers
	deferStacks defers.Results

	// paths[i][j] means there is a path from i to j
	paths map[*ssa.BasicBlock]map[*ssa.BasicBlock]ConditionInfo

	// instrPrev maps instruction to all their potentially preceding instructions. This is used by the analysis to
	// transfer the abstract state in the flowInfo of an instruction to the next instruction
	instrPrev map[ssa.Instruction]map[ssa.Instruction]bool

	// paramAliases maps values to the function to the parameter it aliases
	paramAliases map[ssa.Value]map[*ssa.Parameter]bool

	// freeVarAliases maps values to the free variable it aliases
	freeVarAliases map[ssa.Value]map[*ssa.FreeVar]bool

	// shouldTrack returns true if dataflow from the ssa node should be tracked
	shouldTrack func(*config.Config, ssa.Node) bool

	// postBlockCallback is called after each block if it is non-nil. Useful for debugging purposes.
	postBlockCallback func(*AnalysisState)
}

// initialize initializes the state of the analysis
// initialize should only be called on non-empty functions (non-empty state.summary.Parent)
func (state *AnalysisState) initialize() {
	function := state.summary.Parent

	// initialize should only be called on non-empty functions
	if len(function.Blocks) == 0 || len(function.Blocks[0].Instrs) == 0 {
		return
	}

	firstInstr := function.Blocks[0].Instrs[0]
	populateInstrPrevMap(state, firstInstr, function)

	// Initialize alias maps
	lang.IterateValues(function, func(_ int, v ssa.Value) {
		state.paramAliases[v] = map[*ssa.Parameter]bool{}
		state.freeVarAliases[v] = map[*ssa.FreeVar]bool{}
	})
	lang.IterateInstructions(function, func(_ int, i ssa.Instruction) {
		state.flowInfo.MarkedValues[i] = map[ssa.Value]map[Mark]bool{}
	})

	// The free variables of the function are marked
	for _, fv := range function.FreeVars {
		state.flowInfo.AddMark(firstInstr, fv, NewMark(fv, FreeVar, "", nil, -1))
		state.addFreeVarAliases(fv)
	}
	// The parameters of the function are marked as Parameter
	for _, param := range function.Params {
		state.flowInfo.AddMark(firstInstr, param, NewMark(param, Parameter, "", nil, -1))
		state.addParamAliases(param)
	}

	// Special cases: load instructions in closures
	lang.IterateInstructions(function,
		func(_ int, i ssa.Instruction) {
			if load, ok := i.(*ssa.UnOp); ok && load.Op == token.MUL {
				for _, fv := range function.FreeVars {
					if fv == load.X {
						state.freeVarAliases[load][fv] = true
					}
				}
			}
		})

	// Collect global variable uses
	lang.IterateInstructions(function,
		func(_ int, i ssa.Instruction) {
			var operands []*ssa.Value
			operands = i.Operands(operands)
			for _, operand := range operands {
				// Add marks for globals
				if glob, ok := (*operand).(*ssa.Global); ok {
					if node, ok := state.cache.Globals[glob]; ok {
						state.summary.AddAccessGlobalNode(i, node)
					}
				}
			}
		})
}

func populateInstrPrevMap(tracker *AnalysisState, firstInstr ssa.Instruction, function *ssa.Function) {
	tracker.instrPrev[firstInstr] = map[ssa.Instruction]bool{firstInstr: true}
	var prevInstr ssa.Instruction
	for _, block := range function.Blocks {
		for j, instr := range block.Instrs {
			tracker.instrPrev[instr] = map[ssa.Instruction]bool{}
			if j == 0 {
				for _, pred := range block.Preds {
					if pred != nil && len(pred.Instrs) > 0 {
						last := pred.Instrs[len(pred.Instrs)-1]
						tracker.instrPrev[instr][last] = true
					}
				}
			} else if prevInstr != nil {
				tracker.instrPrev[instr][prevInstr] = true
			}
			prevInstr = instr
		}
	}

	// Special case: because of panics, we assume the previous instruction of a rundefer can be any instruction before
	// it
	lang.IterateInstructions(function, func(_ int, instr ssa.Instruction) {
		if _, ok := instr.(*ssa.RunDefers); ok {
			for _, block := range function.Blocks {
				for _, i := range block.Instrs {
					if tracker.checkPathBetweenInstructions(i, instr).Satisfiable {
						tracker.instrPrev[i][instr] = true
					}
				}
			}
		}
	})
}

// Pre is executed before an instruction is visited. For the dataflow analysis, Pre transfers all the reachable
// values of the previous instruction to the current instruction.
func (state *AnalysisState) Pre(ins ssa.Instruction) {
	for predecessor := range state.instrPrev[ins] {
		for value, marks := range state.flowInfo.MarkedValues[predecessor] {
			if _, ok := state.flowInfo.MarkedValues[ins][value]; !ok {
				state.flowInfo.MarkedValues[ins][value] = map[Mark]bool{}
				state.changeFlag = true
			}
			for mark := range marks {
				if !state.flowInfo.MarkedValues[ins][value][mark] {
					state.flowInfo.MarkedValues[ins][value][mark] = true
					state.changeFlag = true
				}
			}
		}
	}
}

// Post is applied after every instruction. This is necessary to satisfy the interface, and can also be used for
// debugging purposes
func (state *AnalysisState) Post(_ ssa.Instruction) {

}

// getMarkedValues returns a mark and true if v is a marked value at instruction i, otherwise it returns (nil, false)
// Uses both the direct taint information in the taint tracking info, and the pointer taint information, i.e:
// - A value is marked if it is directly marked
// - A value is marked if it is a pointer and some alias is marked.
// The path parameter enables path-sensitivity. If path is "*", any path is accepted and the analysis
// over-approximates.
func (state *AnalysisState) getMarkedValues(i ssa.Instruction, v ssa.Value, path string) []Mark {
	var origins []Mark
	// when the value is directly marked as tainted.
	for mark := range state.flowInfo.MarkedValues[i][v] {
		if path == "*" || mark.RegionPath == path || mark.RegionPath == "*" || mark.RegionPath == "" {
			origins = append(origins, mark)
		}
	}

	return origins
}

// simpleTransfer  propagates all the marks from in to out, ignoring path and tuple indexes
func simpleTransfer(t *AnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value) {
	transfer(t, loc, in, out, "*", -1)
}

// transfer propagates all the marks from in to out with the object path string
// an index >= 0 indicates that element index of the tuple in is accessed
func transfer(t *AnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value, path string, index int) {
	if glob, ok := in.(*ssa.Global); ok {
		t.markValue(loc, out, NewMark(loc.(ssa.Node), Global, "", glob, index))
	}

	for _, origin := range t.getMarkedValues(loc, in, path) {
		newOrigin := origin
		if index >= 0 {
			newOrigin = NewMark(origin.Node, origin.Type, origin.RegionPath, origin.Qualifier, index)
		}
		t.markValue(loc, out, newOrigin)
		t.checkCopyIntoArgs(newOrigin, out)
		t.checkFlowIntoGlobal(loc, newOrigin, out)
	}
}

// addClosureNode adds a closure node to the graph, and all the related sources and edges.
// The closure value is tracked like any other value.
func (state *AnalysisState) addClosureNode(x *ssa.MakeClosure) {
	state.summary.AddClosure(x)
	state.markValue(x, x, NewMark(x, Closure, "", nil, -1))
	for _, boundVar := range x.Bindings {
		mark := NewMark(x, BoundVar, "", boundVar, -1)
		state.markValue(x, boundVar, mark)
	}
	state.markValue(x, x, NewMark(x, Closure, "", nil, -1))
}

// optionalSyntheticNode tracks the flow of data from a synthetic node.
func (state *AnalysisState) optionalSyntheticNode(asValue ssa.Value, asInstr ssa.Instruction, asNode ssa.Node) {
	if state.shouldTrack(state.cache.Config, asNode) {
		s := NewMark(asNode, Synthetic+DefaultMark, "", nil, -1)
		state.summary.AddSyntheticNode(asInstr, "source")
		state.markValue(asInstr, asValue, s)
	}
}

// callCommonMark can be used for Call and Go instructions that wrap a CallCommon. For a function call, the value,
// instruction and common are the same object (x = value = instr and common = x.Common()) but for Go and Defers
// this varies.
func (state *AnalysisState) callCommonMark(value ssa.Value, instr ssa.CallInstruction, common *ssa.CallCommon) {
	// Special cases
	if doBuiltinCall(state, value, common, instr) {
		return
	}
	state.summary.AddCallInstr(state.cache, instr)
	// Check if node is source according to config
	markType := CallReturn
	if state.shouldTrack(state.flowInfo.Config, instr.(ssa.Node)) { // type cast cannot fail
		markType += DefaultMark
	}
	// Mark call, one mark per returned value
	res := common.Signature().Results()
	if res.Len() > 0 {
		for i := 0; i < res.Len(); i++ {
			state.markValue(instr, value, NewMark(instr.(ssa.Node), markType, "", nil, i))
		}
	} else {
		state.markValue(instr, value, NewMark(instr.(ssa.Node), markType, "", nil, -1))
	}

	args := lang.GetArgs(instr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Mark call argument
		state.markValue(instr, arg, NewMark(instr.(ssa.Node), CallSiteArg, "", arg, -1))
	}
}

// Checking mark flows into specific locations:
// checkCopyIntoArgs checks flows into args/free variables that will be observed by the caller of the function when
// the callee returns
// checkFlowIntoGlobal checks whether the data is flowing into a global location, in which case an edge needs to be
// added.
// TODO: think about moving those functions to the edge building phase

// checkCopyIntoArgs checks whether the mark in is copying or writing into a value that aliases with
// one of the function's parameters. This keeps tracks of data flows to the function parameters that a
// caller might see.
func (state *AnalysisState) checkCopyIntoArgs(in Mark, out ssa.Value) {
	if lang.IsNillableType(out.Type()) {
		for aliasedParam := range state.paramAliases[out] {
			state.summary.AddParamEdge(in, aliasedParam, nil)
		}
		for aliasedFreeVar := range state.freeVarAliases[out] {
			state.summary.AddFreeVarEdge(in, aliasedFreeVar, nil)
		}
	}
}

// checkFlowIntoGlobal checks whether the origin is data flowing into a global variable
func (state *AnalysisState) checkFlowIntoGlobal(loc ssa.Instruction, origin Mark, out ssa.Value) {
	if glob, isGlob := out.(*ssa.Global); isGlob {
		state.summary.AddGlobalEdge(origin, loc, glob, nil)
	}
}

// Marking values:
// the functions markValue and markAllAliases are used to mark values. markAllAliases should not be called directly
// unless some special logic is required. markValue will automatically call markAllAliases

// markValue marks the value v and all values that propagate from v.
// If the value was not marked, it changes the changeFlag to true to indicate
// that the mark information has changed for the current pass.
func (state *AnalysisState) markValue(i ssa.Instruction, v ssa.Value, mark Mark) {
	if state.flowInfo.HasMarkAt(i, v, mark) {
		return
	}
	// v was not marked before
	state.changeFlag = state.flowInfo.AddMark(i, v, mark)
	// Propagate to any other value that is an alias of v
	// By direct query
	if ptr, ptrExists := state.cache.PointerAnalysis.Queries[v]; ptrExists {
		state.markAllAliases(i, mark, ptr)
	}
	// By indirect query
	if ptr, ptrExists := state.cache.PointerAnalysis.IndirectQueries[v]; ptrExists {
		state.markAllAliases(i, mark, ptr)
	}

	switch miVal := v.(type) {
	case *ssa.MakeInterface:
		// SPECIAL CASE: value is result of make any <- v', mark v'
		// handles cases where a function f(_ any...) is called on some argument of concrete type
		// conversion to any or interface{}
		typStr := miVal.Type().String()
		if typStr == "any" || typStr == "interface{}" {
			state.markValue(i, miVal.X, mark)
		}
	case *ssa.IndexAddr:
		// mark the whole array
		state.markValue(i, miVal.X, mark)
	case *ssa.Index:
		state.markValue(i, miVal.X, mark)
	case *ssa.Field:
		state.markValue(i, miVal.X, mark)
	case *ssa.FieldAddr:
		state.markValue(i, miVal.X, mark)
	}
}

// markAllAliases marks all the aliases of the pointer set using mark.
func (state *AnalysisState) markAllAliases(i ssa.Instruction, mark Mark, ptr pointer.Pointer) {
	// Look at every value in the points-to set.
	for _, label := range ptr.PointsTo().Labels() {
		if label != nil && label.Value() != nil {
			// mark.RegionPath = label.Path() // will use path for field sensitivity
			state.flowInfo.AddMark(i, label.Value(), mark)
		}
	}

	// Iterate over all values in the function, scanning for aliases of ptr, and mark the values that match
	lang.IterateValues(state.summary.Parent, func(_ int, value ssa.Value) {
		if ptr2, ptrExists := state.cache.PointerAnalysis.IndirectQueries[value]; ptrExists && ptr2.MayAlias(ptr) {
			state.markValue(i, value, mark)
		}
		if ptr2, ptrExists := state.cache.PointerAnalysis.Queries[value]; ptrExists && ptr2.MayAlias(ptr) {
			state.markValue(i, value, mark)
		}
	})
}

// --- Defers analysis ---

func (state *AnalysisState) getInstr(blockNum int, instrNum int) (ssa.Instruction, error) {
	block := state.summary.Parent.Blocks[blockNum]
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
func (state *AnalysisState) doDefersStackSimulation(r *ssa.RunDefers) error {
	stackSet := state.deferStacks.RunDeferSets[r]
	for _, stack := range stackSet {
		// Simulate a new block
		state.NewBlock(r.Block())
		for _, instrIndex := range stack {
			instr, err := state.getInstr(instrIndex.Block, instrIndex.Ins)
			if err != nil {
				return err
			}
			if d, ok := instr.(*ssa.Defer); ok {
				state.callCommonMark(d.Value(), d, d.Common())
			} else {
				return fmt.Errorf("defer stacks should only contain defers")
			}
		}
	}
	return nil
}

// --- Pointer analysis querying ---

// getAnyPointer returns the pointer to x according to the pointer analysis
func (state *AnalysisState) getPointer(x ssa.Value) *pointer.Pointer {
	if ptr, ptrExists := state.cache.PointerAnalysis.Queries[x]; ptrExists {
		return &ptr
	}
	return nil
}

// getAnyPointer returns the pointer to x according to the pointer analysis
func (state *AnalysisState) getIndirectPointer(x ssa.Value) *pointer.Pointer {
	// Check indirect queries
	if ptr, ptrExists := state.cache.PointerAnalysis.IndirectQueries[x]; ptrExists {
		return &ptr
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

		lang.IterateValues(f, func(_ int, v ssa.Value) {
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

// addParamAliases collects information about the value-aliases of the parameters
func (state *AnalysisState) addParamAliases(x *ssa.Parameter) {
	state.paramAliases[x][x] = true
	addAliases(x, state.summary.Parent, state.getPointer(x),
		state.paramAliases, state.getPointer, state.getIndirectPointer)
	addAliases(x, state.summary.Parent, state.getIndirectPointer(x),
		state.paramAliases, state.getPointer, state.getIndirectPointer)
}

// addFreeVarAliases collects information about the value-aliases of the free variables
func (state *AnalysisState) addFreeVarAliases(x *ssa.FreeVar) {
	state.freeVarAliases[x][x] = true
	addAliases(x, state.summary.Parent, state.getPointer(x),
		state.freeVarAliases, state.getPointer, state.getIndirectPointer)
	addAliases(x, state.summary.Parent, state.getIndirectPointer(x),
		state.freeVarAliases, state.getPointer, state.getIndirectPointer)
}

func (state *AnalysisState) FlowInfo() *FlowInformation {
	return state.flowInfo
}

func (state *AnalysisState) Block() *ssa.BasicBlock {
	return state.curBlock
}
