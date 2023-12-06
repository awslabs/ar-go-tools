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

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// IntraAnalysisState contains the information used by the intra-procedural dataflow analysis.
type IntraAnalysisState struct {
	// the data flow information for the analysis
	flowInfo *FlowInformation

	// the analysis parentAnalyzerState containing pointer information, callgraph, ...
	parentAnalyzerState *AnalyzerState

	// changeFlag keeps track of changes in the analysis state and is reset each time a new block is visited
	changeFlag bool

	// curBlock keeps track of the curren block
	curBlock *ssa.BasicBlock

	// blocksSeen is a slice mapping block indexes to a boolean indicating if the block was seen
	blocksSeen []bool

	// errors stores the errors met during the analysis. We don't panic during the analysis, but accumulate errors and
	// the client is responsible for proper handling of the errors
	errors map[ssa.Node]error

	// summary is the function summary currently being built. The function being analyzed is the Parent of the summary.
	summary *SummaryGraph

	// deferStacks contains information about the possible defer stacks at RunDefers
	deferStacks defers.Results

	// paths[i * numBlocks + j] means there is a Path from block indexed i to block indexed  j
	paths []*ConditionInfo

	// instrPrev maps instruction ids to all their potentially preceding instructions. This is used by the analysis to
	// transfer the abstract state in the flowInfo of an instruction to the next instruction
	instrPrev []map[int]bool

	// paramAliases maps values to the function to the parameter it aliases
	paramAliases []map[*ssa.Parameter]bool

	// freeVarAliases maps values to the free variable it aliases
	freeVarAliases []map[*ssa.FreeVar]bool

	valueAliases [][]ValueWithAccessPath

	// shouldTrack returns true if dataflow from the ssa node should be tracked
	shouldTrack func(*config.Config, *pointer.Result, ssa.Node) bool

	// postBlockCallback is called after each block if it is non-nil. Useful for debugging purposes.
	postBlockCallback func(*IntraAnalysisState)
}

// initialize initializes the state of the analysis
// initialize should only be called on non-empty functions (non-empty state.summary.Parent)
func (state *IntraAnalysisState) initialize() {
	if state.flowInfo == nil {
		panic("AnalysisState must be initialized with initialized flowInfo")
	}

	function := state.summary.Parent
	// initialize should only be called on non-empty functions
	if len(function.Blocks) == 0 || len(function.Blocks[0].Instrs) == 0 {
		return
	}

	firstInstr := function.Blocks[0].Instrs[0]
	populateInstrPrevMap(state, firstInstr, function)

	// Initialize alias maps
	for _, id := range state.flowInfo.ValueId {
		state.paramAliases[id] = map[*ssa.Parameter]bool{}
		state.freeVarAliases[id] = map[*ssa.FreeVar]bool{}
	}

	// The free variables of the function are marked
	for _, fv := range function.FreeVars {
		state.flowInfo.AddMark(firstInstr, fv, "", state.flowInfo.GetNewMark(fv, FreeVar, nil, -1))
		state.addFreeVarAliases(fv)
	}
	// The parameters of the function are marked as Parameter
	for _, param := range function.Params {
		state.flowInfo.AddMark(firstInstr, param, "", state.flowInfo.GetNewMark(param, Parameter, nil, -1))
		state.addParamAliases(param)
	}

	// Special cases: load instructions in closures
	lang.IterateInstructions(function,
		func(_ int, i ssa.Instruction) {
			if load, ok := i.(*ssa.UnOp); ok && load.Op == token.MUL {
				for _, fv := range function.FreeVars {
					if fv == load.X {
						state.freeVarAliases[state.flowInfo.ValueId[load]][fv] = true
					}
				}
			}
		})
}

// populateInstrPrevMap populates the instrPrev map in the intra analysis state. Once this function has been called,
// intraState.instrPrev maps instructions to the preceding instructions in the function. In a block, the preceding
// instruction is the instruction before in the block. At the beginning of the block, the preceding instructions are
// the last instruction of each of the predecessor blocks.
//
// We make a special case for instructions in defer statements: we assume that any instruction before a [ssa.RunDefers]
// (and not a [ssa.Defer]!) can be a preceding instruction. This over-approximates program executions where any instruction
// can panic.
func populateInstrPrevMap(intraState *IntraAnalysisState, firstInstr ssa.Instruction, function *ssa.Function) {
	firstId := intraState.flowInfo.InstrId[firstInstr]
	intraState.instrPrev[firstId] = map[int]bool{firstId: true}
	var prevInstr ssa.Instruction
	for _, block := range function.Blocks {
		for j, instr := range block.Instrs {
			instrId := intraState.flowInfo.InstrId[instr]
			intraState.instrPrev[instrId] = map[int]bool{}
			if j == 0 {
				for _, pred := range block.Preds {
					if pred != nil && len(pred.Instrs) > 0 {
						last := pred.Instrs[len(pred.Instrs)-1]
						lastId := intraState.flowInfo.InstrId[last]
						intraState.instrPrev[instrId][lastId] = true
					}
				}
			} else if prevInstr != nil {
				prevId := intraState.flowInfo.InstrId[prevInstr]
				intraState.instrPrev[instrId][prevId] = true
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
					iId := intraState.flowInfo.InstrId[i]
					if intraState.checkPathBetweenInstructions(i, instr).Satisfiable {
						instrId := intraState.flowInfo.InstrId[instr]
						intraState.instrPrev[iId][instrId] = true
					}
				}
			}
		}
	})
}

// Pre is executed before an instruction is visited. For the dataflow analysis, Pre transfers all the reachable
// values of the previous instruction to the current instruction;
// Pre ensures that the analysis is a monotone analysis.
func (state *IntraAnalysisState) Pre(ins ssa.Instruction) {
	ix := state.flowInfo.GetInstrPos(ins)
	n := state.flowInfo.NumValues
	for pIndex := range state.instrPrev[state.flowInfo.InstrId[ins]] {
		for valueNum, previousAbstractValue := range state.flowInfo.MarkedValues[pIndex*n : pIndex*n+n] {
			curAbstractValue := state.flowInfo.MarkedValues[ix+valueNum]
			if curAbstractValue == nil {
				curAbstractValue = NewAbstractValue(state.flowInfo.values[valueNum],
					state.flowInfo.pathSensitivityFilter[valueNum])
				state.flowInfo.MarkedValues[ix+valueNum] = curAbstractValue
				state.changeFlag = true
			}
			if previousAbstractValue.mergeInto(curAbstractValue) {
				state.changeFlag = true
			}
		}
	}
}

// Post is applied after every instruction. This is necessary to satisfy the interface, and can also be used for
// debugging purposes.
func (state *IntraAnalysisState) Post(_ ssa.Instruction) {

}

// getMarks returns a mark and true if v is a marked Value at instruction i, otherwise it returns (nil, false)
// Uses both the direct taint information in the taint tracking info, and the pointer taint information, i.e:
// - A Value is marked if it is directly marked
// - A Value is marked if it is a pointer and some alias is marked.
// The Path parameter enables Path-sensitivity. If Path is "*", any Path is accepted and the analysis
// over-approximates.
func (state *IntraAnalysisState) getMarks(i ssa.Instruction, v ssa.Value, path string,
	isProceduralEntry bool, ignorePath bool) []MarkWithAccessPath {
	index := state.flowInfo.GetPos(i, v)
	var origins []MarkWithAccessPath
	values := state.valueAliases[index]
	if values == nil {
		values = state.getValueAliases(i, v, isProceduralEntry)
		state.valueAliases[index] = values
	}

	for _, alias := range values {
		if alias.FromProcEntry && !isProceduralEntry {
			continue
		}
		aliasIndex := state.flowInfo.GetPos(alias.Instruction, alias.Value)
		if aliasIndex < 0 {
			continue // this ia not a value inside the function
		}
		if ignorePath {
			for _, mark := range state.flowInfo.MarkedValues[aliasIndex].AllMarks() {
				origins = append(origins, mark)
			}
		} else {
			for _, mark := range state.flowInfo.MarkedValues[aliasIndex].MarksAt(path) {
				origins = append(origins, mark)
			}
		}
	}
	return origins
}

func (state *IntraAnalysisState) getValueAliases(i ssa.Instruction, v ssa.Value, p bool) []ValueWithAccessPath {
	var computedValues []ValueWithAccessPath
	state.getValueAliasesRec(&computedValues, i, v, "", p, map[ValueWithAccessPath]bool{})
	return computedValues
}

func (state *IntraAnalysisState) getValueAliasesRec(values *[]ValueWithAccessPath, i ssa.Instruction, v ssa.Value,
	relPath string,
	isProceduralEntry bool,
	queries map[ValueWithAccessPath]bool) {

	val := ValueWithAccessPath{v, i, "", isProceduralEntry}
	if queries[val] || v == nil {
		return
	}
	*values = append(*values, val)
	queries[val] = true

	if isProceduralEntry {
		if _, isCall := v.(*ssa.Call); !isCall {
			// If any of the aliases of the value is marked, add the marks
			for _, ptr := range state.findAllPointers(v) {
				for _, label := range ptr.PointsTo().Labels() {
					state.getValueAliasesRec(values, i, label.Value(), relPath, true, queries)
				}
			}

			// inspect specific referrer to see if they are marked
			referrers := v.Referrers()
			if referrers != nil {
				for _, referrer := range *(v.Referrers()) {
					state.referrerAliases(values, i, v, relPath, referrer, queries)
				}
			}
		}
	}
}

//gocyclo:ignore
func (state *IntraAnalysisState) referrerAliases(values *[]ValueWithAccessPath, i ssa.Instruction, v ssa.Value,
	path string, referrer ssa.Instruction, queries map[ValueWithAccessPath]bool) {
	switch refInstr := referrer.(type) {
	case *ssa.Send:
		// marks on a Value sent on a channel transfer to channel
		if v == refInstr.Chan && lang.IsNillableType(refInstr.X.Type()) {
			state.getValueAliasesRec(values, i, refInstr.X, path, true, queries)
			return
		}
	case *ssa.FieldAddr:
		// refInstr is "y = &v.name"
		// the Value is the struct, collect the marks on the field address. We are not field sensitive, so if the
		// field address has marks, then the struct itself has marks.
		state.getValueAliasesRec(values, i, refInstr, pathAppendField(path, analysisutil.FieldAddrFieldName(refInstr)), true, queries)
		return
	case *ssa.IndexAddr:
		// the marks on an index address transfer to the slice (but not the marks on the index)
		if v != refInstr.Index {
			state.getValueAliasesRec(values, i, refInstr, pathAppendIndexing(path), true, queries)
			return
		}
	case *ssa.Slice:
		// the marks of a slice of the Value are also marks of the Value
		if v == refInstr.X {
			state.getValueAliasesRec(values, i, refInstr, path, true, queries)
			return
		}
	case *ssa.Store:
		// is a Value is stored, and that Value is pointer like, the marks transfer to the address
		if v == refInstr.Addr && lang.IsNillableType(refInstr.Val.Type()) {
			state.getValueAliasesRec(values, i, refInstr.Val, path, true, queries)
			return
		}
	case *ssa.MapUpdate:
		// inspect marks of referrers, but only when the referred Value is the map (the Value or key does not flow
		// to the adjacent Value/key).
		// The location of the mark transfer (flowRef) depends on whether the object written to the map is pointer
		// like or not, like in Store
		if v != refInstr.Value && v != refInstr.Key {
			// Value
			flowRef := (ssa.Instruction)(refInstr)
			if lang.IsNillableType(refInstr.Value.Type()) {
				flowRef = i
			}
			state.getValueAliasesRec(values, flowRef, refInstr.Value, pathAppendIndexing(path), true, queries)

			// Key
			flowRef = (ssa.Instruction)(refInstr)
			if lang.IsNillableType(refInstr.Key.Type()) {
				flowRef = i
			}
			state.getValueAliasesRec(values, flowRef, refInstr.Key, pathAppendIndexing(path), true, queries)
			return
		}
	}
}

// simpleTransfer  propagates all the marks from in to out, ignoring Path and tuple indexes
func simpleTransfer(state *IntraAnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value) {
	transfer(state, loc, in, out, "", -1)
}

// transfer propagates all the marks from in to out with the object Path string
// an index >= 0 indicates that element index of the tuple in is accessed
func transfer(state *IntraAnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value, path string, index int) {
	if glob, ok := in.(*ssa.Global); ok {
		state.markValue(loc, out, "", state.flowInfo.GetNewMark(loc.(ssa.Node), Global, glob, index))
	}

	for _, origin := range state.getMarks(loc, in, path, false, false) {
		state.flowInfo.SetLoc(origin.Mark, loc)
		newOrigin := origin.Mark
		if index >= 0 {
			newOrigin = state.flowInfo.GetNewMark(origin.Mark.Node, origin.Mark.Type, origin.Mark.Qualifier, index)
		}
		state.markValue(loc, out, origin.AccessPath, newOrigin)
	}

	state.checkFlowIntoGlobal(loc, in, out)
}

// transferCopy propagates the marks for a load, which only requires copying over marks and paths
func transferCopy(t *IntraAnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value) {
	aState := t.flowInfo.MarkedValues[t.flowInfo.GetPos(loc, in)]
	for _, markWithPath := range aState.AllMarks() {
		t.markValue(loc, out, markWithPath.AccessPath, markWithPath.Mark)
	}
}

// markClosureNode adds a closure node to the graph, and all the related sources and edges.
// The closure Value is tracked like any other Value.
func (state *IntraAnalysisState) markClosureNode(x *ssa.MakeClosure) {
	state.markValue(x, x, "", state.flowInfo.GetNewMark(x, Closure, nil, -1))
	for _, boundVar := range x.Bindings {
		mark := state.flowInfo.GetNewMark(x, BoundVar, boundVar, -1)
		state.markValue(x, boundVar, "", mark)
	}
}

// optionalSyntheticNode tracks the flow of data from a synthetic node.
func (state *IntraAnalysisState) optionalSyntheticNode(asValue ssa.Value, asInstr ssa.Instruction, asNode ssa.Node) {
	if state.shouldTrack(state.parentAnalyzerState.Config, state.parentAnalyzerState.PointerAnalysis, asNode) {
		s := state.flowInfo.GetNewMark(asNode, Synthetic+DefaultMark, nil, -1)
		state.markValue(asInstr, asValue, "", s)
	}
}

// callCommonMark can be used for Call and Go instructions that wrap a CallCommon. For a function call, the Value,
// instruction and common are the same object (x = Value = instr and common = x.Common()) but for Go and Defers
// this varies.
func (state *IntraAnalysisState) callCommonMark(value ssa.Value, instr ssa.CallInstruction, common *ssa.CallCommon) {
	// Special cases
	if doBuiltinCall(state, value, common, instr) {
		return
	}
	// Check if node is source according to config
	markType := CallReturn
	if state.shouldTrack(state.parentAnalyzerState.Config,
		state.parentAnalyzerState.PointerAnalysis,
		instr.(ssa.Node)) {
		markType += DefaultMark
	}
	// Mark call, one mark per returned Value
	res := common.Signature().Results()
	if res.Len() > 0 {
		for i := 0; i < res.Len(); i++ {
			state.markValue(instr, value, "", state.flowInfo.GetNewMark(instr.(ssa.Node), markType, nil, i))
		}
	} else {
		state.markValue(instr, value, "", state.flowInfo.GetNewMark(instr.(ssa.Node), markType, nil, -1))
	}

	args := lang.GetArgs(instr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Mark call argument
		newMark := state.flowInfo.GetNewMark(instr.(ssa.Node), CallSiteArg, arg, -1)
		state.markValue(instr, arg, "", newMark)
	}
}

// Checking mark flows into specific locations:
// checkCopyIntoArgs checks flows into args/free variables that will be observed by the caller of the function when
// the callee returns
// checkFlowIntoGlobal checks whether the data is flowing into a global location, in which case an edge needs to be
// added.
// TODO: think about moving those functions to the edge building phase

// checkCopyIntoArgs checks whether the mark in is copying or writing into a Value that aliases with
// one of the function's parameters. This keeps tracks of data flows to the function parameters that a
// caller might see.
func (state *IntraAnalysisState) checkCopyIntoArgs(in *Mark, out ssa.Value) {
	vid := state.flowInfo.GetValueId(out)
	if vid >= 0 && lang.IsNillableType(out.Type()) {
		for aliasedParam := range state.paramAliases[vid] {
			state.summary.addParamEdge(in, nil, aliasedParam)
		}
		for aliasedFreeVar := range state.freeVarAliases[vid] {
			state.summary.addFreeVarEdge(in, nil, aliasedFreeVar)
		}
	}
}

// checkFlowIntoGlobal checks whether the origin is data flowing into a global variable
func (state *IntraAnalysisState) checkFlowIntoGlobal(loc ssa.Instruction, in, out ssa.Value) {
	glob, isGlob := out.(*ssa.Global)
	if !isGlob {
		return
	}
	for _, origin := range state.getMarks(loc, in, "", true, true) {
		state.summary.addGlobalEdge(origin.Mark, nil, loc, glob)
	}
}

// Marking values:
// the functions markValue and markAllAliases are used to mark values. markAllAliases should not be called directly
// unless some special logic is required. markValue will automatically call markAllAliases

// markValue marks the Value v and all values that propagate from v.
// If the Value was not marked, it changes the changeFlag to true to indicate
// that the mark information has changed for the current pass.
func (state *IntraAnalysisState) markValue(i ssa.Instruction, v ssa.Value, path string, mark *Mark) {
	if state.flowInfo.HasMarkAt(i, v, path, mark) {
		return
	}
	// v was not marked before
	state.changeFlag = state.flowInfo.AddMark(i, v, path, mark)
	// Propagate to any other Value that is an alias of v
	for _, ptr := range state.findAllPointers(v) {
		state.markPtrAliases(i, mark, path, ptr)
	}

	switch miVal := v.(type) {
	case *ssa.Slice:
		state.markValue(i, miVal.X, path, mark)
	case *ssa.MakeInterface:
		// SPECIAL CASE: Value is result of make any <- v', mark v'
		// handles cases where a function f(_ any...) is called on some argument of concrete type
		// conversion to any or interface{}
		typStr := miVal.Type().String()
		if typStr == "any" || typStr == "interface{}" {
			state.markValue(i, miVal.X, path, mark)
		}
	case *ssa.IndexAddr:
		state.markValue(i, miVal.X, pathPrependIndexing(path), mark)
	case *ssa.Index:
		state.markValue(i, miVal.X, pathPrependIndexing(path), mark)
	case *ssa.Field:
		state.markValue(i, miVal.X, pathPrependField(path, analysisutil.FieldFieldName(miVal)), mark)
	case *ssa.FieldAddr:
		state.markValue(i, miVal.X, pathPrependField(path, analysisutil.FieldAddrFieldName(miVal)), mark)
	}

	// Propagate to select referrers
	if _, isCall := v.(*ssa.Call); !isCall {
		referrers := v.Referrers()
		if referrers != nil {
			for _, referrer := range *referrers {
				state.propagateToReferrer(i, referrer, v, mark, path)
			}
		}
	}
}

func (state *IntraAnalysisState) propagateToReferrer(i ssa.Instruction, ref ssa.Instruction, v ssa.Value, mark *Mark,
	path string) {
	switch referrer := ref.(type) {
	case *ssa.Store:
		if referrer.Val == v && lang.IsNillableType(referrer.Val.Type()) {
			state.markValue(i, referrer.Addr, path, mark)
		}
	case *ssa.IndexAddr:
		// this referrer accesses the marked value's index
		path2, ok := pathMatchIndex(path)
		if ok && referrer.X == v {
			state.markValue(i, referrer, path2, mark)
		}
	case *ssa.FieldAddr:
		// this referrer accesses the marked value's field
		path2, ok := pathMatchField(path, analysisutil.FieldAddrFieldName(referrer))
		if referrer.X == v && ok {
			state.markValue(i, referrer, path2, mark)
		}
	case *ssa.UnOp:
		// this referrer dereferences the marked value
		if referrer.Op == token.MUL {
			state.markValue(i, referrer, path, mark)
		} else if referrer.Op == token.ARROW {
			state.markValue(i, referrer, path, mark)
		}
	}
}

func (state *IntraAnalysisState) findAllPointers(v ssa.Value) []pointer.Pointer {
	var allptr []pointer.Pointer
	if ptr, ptrExists := state.parentAnalyzerState.PointerAnalysis.Queries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	// By indirect query
	if ptr, ptrExists := state.parentAnalyzerState.PointerAnalysis.IndirectQueries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	return allptr
}

// markAllAliases marks all the aliases of the pointer set using mark.
func (state *IntraAnalysisState) markPtrAliases(i ssa.Instruction, mark *Mark, path string, ptr pointer.Pointer) {
	// Look at every Value in the points-to set.
	for _, label := range ptr.PointsTo().Labels() {
		if label != nil && label.Value() != nil {
			state.flowInfo.AddMark(i, label.Value(), label.Path()+path, mark)
		}
	}

	// Iterate over all values in the function, scanning for aliases of ptr, and mark the values that match
	lang.IterateValues(state.summary.Parent, func(_ int, value ssa.Value) {
		for _, ptr2 := range state.findAllPointers(value) {
			if ptr2.MayAlias(ptr) {
				state.markValue(i, value, path, mark)
			}
		}
	})
}

// --- Defers analysis ---

func (state *IntraAnalysisState) getInstr(blockNum int, instrNum int) (ssa.Instruction, error) {
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
func (state *IntraAnalysisState) doDefersStackSimulation(r *ssa.RunDefers) error {
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
func (state *IntraAnalysisState) getPointer(x ssa.Value) *pointer.Pointer {
	if ptr, ptrExists := state.parentAnalyzerState.PointerAnalysis.Queries[x]; ptrExists {
		return &ptr
	}
	return nil
}

// getAnyPointer returns the pointer to x according to the pointer analysis
func (state *IntraAnalysisState) getIndirectPointer(x ssa.Value) *pointer.Pointer {
	// Check indirect queries
	if ptr, ptrExists := state.parentAnalyzerState.PointerAnalysis.IndirectQueries[x]; ptrExists {
		return &ptr
	}
	return nil
}

// addAliases is a type parametric version of the alias caching functions
func addAliases[T comparable](x T, f *ssa.Function, ptr *pointer.Pointer, aliases []map[T]bool,
	oracleDirect func(value ssa.Value) *pointer.Pointer,
	oracleIndirect func(value ssa.Value) *pointer.Pointer,
	valueIds func(ssa.Value) int) {
	if ptr != nil {
		for _, lb := range ptr.PointsTo().Labels() {
			if lb != nil && lb.Value() != nil && lb.Value().Parent() == f {
				id := valueIds(lb.Value())
				if id >= 0 {
					aliases[id][x] = true
				}
			}
		}

		lang.IterateValues(f, func(_ int, v ssa.Value) {
			vid := valueIds(v)
			ptr2 := oracleIndirect(v)
			if ptr2 != nil && ptr.MayAlias(*ptr2) {
				aliases[vid][x] = true
			}
			ptr3 := oracleDirect(v)
			if ptr3 != nil && ptr.MayAlias(*ptr3) {
				aliases[vid][x] = true
			}
		})
	}
}

// addParamAliases collects information about the Value-aliases of the parameters
func (state *IntraAnalysisState) addParamAliases(x *ssa.Parameter) {
	state.paramAliases[state.flowInfo.GetValueId(x)][x] = true
	addAliases(x, state.summary.Parent, state.getPointer(x),
		state.paramAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueId)
	addAliases(x, state.summary.Parent, state.getIndirectPointer(x),
		state.paramAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueId)
}

// addFreeVarAliases collects information about the Value-aliases of the free variables
func (state *IntraAnalysisState) addFreeVarAliases(x *ssa.FreeVar) {
	state.freeVarAliases[state.flowInfo.GetValueId(x)][x] = true
	addAliases(x, state.summary.Parent, state.getPointer(x),
		state.freeVarAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueId)
	addAliases(x, state.summary.Parent, state.getIndirectPointer(x),
		state.freeVarAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueId)
}

func (state *IntraAnalysisState) FlowInfo() *FlowInformation {
	return state.flowInfo
}

func (state *IntraAnalysisState) Block() *ssa.BasicBlock {
	return state.curBlock
}
