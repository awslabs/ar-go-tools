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
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/defers"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// IntraAnalysisState contains the information used by the intra-procedural dataflow analysis.
type IntraAnalysisState struct {
	// the data flow information for the analysis
	flowInfo *FlowInformation

	// the analysis parentAnalyzerState containing pointer information, callgraph, ...
	parentAnalyzerState *State

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
	instrPrev []map[IndexT]bool

	// paramAliases maps values ids  (ids stored in flowInfo.ValueID)  to the function to the parameter it aliases
	paramAliases []map[*ssa.Parameter]bool

	// freeVarAliases maps values ids (ids stored in flowInfo.ValueID) to the free variable it aliases
	freeVarAliases []map[*ssa.FreeVar]bool

	// shouldTrack returns true if dataflow from the ssa node should be tracked
	shouldTrack func(*State, ssa.Node) bool

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

	firstInstr := state.flowInfo.FirstInstr
	populateInstrPrevMap(state, firstInstr, function)

	// Initialize alias maps
	for _, id := range state.flowInfo.ValueID {
		state.paramAliases[id] = map[*ssa.Parameter]bool{}
		state.freeVarAliases[id] = map[*ssa.FreeVar]bool{}
	}

	// The free variables of the function are marked
	for _, fv := range function.FreeVars {
		if state.flowInfo.pathSensitivityFilter[state.flowInfo.ValueID[fv]] {
			for _, path := range AccessPathsOfType(fv.Type()) {
				state.flowInfo.AddMark(firstInstr, fv, path,
					state.flowInfo.GetNewLabelledMark(fv, FreeVar, nil, NonIndexMark, path))
			}
		}
		state.flowInfo.AddMark(firstInstr, fv, "",
			state.flowInfo.GetNewMark(fv, FreeVar, nil, NonIndexMark))
		state.addFreeVarAliases(fv)
	}
	// The parameters of the function are marked as Parameter
	for _, param := range function.Params {
		if state.flowInfo.pathSensitivityFilter[state.flowInfo.ValueID[param]] {
			for _, path := range AccessPathsOfType(param.Type()) {
				state.flowInfo.AddMark(firstInstr, param, path,
					state.flowInfo.GetNewLabelledMark(param, Parameter, nil, NonIndexMark, path))
			}
		}
		state.flowInfo.AddMark(firstInstr, param, "",
			state.flowInfo.GetNewMark(param, Parameter, nil, NonIndexMark))
		state.addParamAliases(param)
	}

	lang.IterateInstructions(function,
		func(_ int, i ssa.Instruction) {
			// Special case: load instructions in closures
			if load, ok := i.(*ssa.UnOp); ok && load.Op == token.MUL {
				for _, fv := range function.FreeVars {
					if fv == load.X {
						state.freeVarAliases[state.flowInfo.ValueID[load]][fv] = true
					}
				}
			}
			// Also mark synthetic nodes here
			state.markInstruction(i)
		})
}

func (state *IntraAnalysisState) markInstruction(i ssa.Instruction) {
	// Instructions that always require marking the value
	switch instr := i.(type) {
	case *ssa.MakeClosure:
		state.markClosureNode(instr)
	case *ssa.Call:
		state.callCommonMark(instr, instr, instr.Common())
	case *ssa.Go: // Analyze go like a function call, but a dedicated concurrency analysis should be used
		state.callCommonMark(instr.Value(), instr, instr.Common())
	}

	// Instructions where marking is optional
	if state.shouldTrack(state.parentAnalyzerState, i.(ssa.Node)) {
		mark := state.flowInfo.GetNewMark(i.(ssa.Node), Synthetic+DefaultMark, nil, NonIndexMark)
		switch instr := i.(type) {
		case *ssa.UnOp:
			// Receiving from a channel can be a source
			if instr.Op == token.ARROW {
				state.flowInfo.AddMark(i, instr, "", mark)
			}
		case *ssa.Alloc:
			// Allocating a value of a certain type can be a source
			state.flowInfo.AddMark(i, instr, "", mark)
		case *ssa.FieldAddr:
			// Accessing a field can be a source
			state.flowInfo.AddMark(i, instr, "", mark)
		case *ssa.Field:
			// Reading from a field can be a source
			state.flowInfo.AddMark(i, instr, "", mark)
		}
	}
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
	firstID := intraState.flowInfo.InstrID[firstInstr]
	intraState.instrPrev[firstID] = map[IndexT]bool{firstID: true}
	for _, block := range function.Blocks {
		var prevInstr ssa.Instruction
		for _, instr := range block.Instrs {
			instrID, ok := intraState.flowInfo.InstrID[instr]
			if !ok {
				continue
			}
			intraState.instrPrev[instrID] = map[IndexT]bool{}
			if prevInstr == nil {
				for _, pred := range block.Preds {
					if pred != nil && len(pred.Instrs) > 0 {
						last := pred.Instrs[len(pred.Instrs)-1]
						lastID, _ := intraState.flowInfo.InstrID[last]
						intraState.instrPrev[instrID][lastID] = true
					}
				}
				prevInstr = instr
			} else {
				prevId := intraState.flowInfo.InstrID[prevInstr]
				intraState.instrPrev[instrID][prevId] = true
				prevInstr = instr
			}
		}
	}

	// Special case: because of panics, we assume the previous instruction of a rundefer can be any instruction before
	// it
	lang.IterateInstructions(function, func(_ int, instr ssa.Instruction) {
		if _, ok := instr.(*ssa.RunDefers); ok {
			for _, block := range function.Blocks {
				for _, i := range block.Instrs {
					iId := intraState.flowInfo.InstrID[i]
					if !isInstrIgnored(i) && intraState.checkPathBetweenInstructions(i, instr).Satisfiable {
						instrID := intraState.flowInfo.InstrID[instr]
						intraState.instrPrev[iId][instrID] = true
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
	if isInstrIgnored(ins) {
		return
	}
	ix := state.flowInfo.GetInstrPos(ins)
	n := state.flowInfo.NumValues
	for pIndex := range state.instrPrev[state.flowInfo.InstrID[ins]] {
		for valueNum, previousAbstractValue := range state.flowInfo.MarkedValues[pIndex*n : pIndex*n+n] {
			vNum := IndexT(valueNum)
			curAbstractValue := state.flowInfo.MarkedValues[ix+vNum]
			if curAbstractValue == nil {
				curAbstractValue = NewAbstractValue(state.flowInfo.values[valueNum],
					state.flowInfo.pathSensitivityFilter[valueNum])
				state.flowInfo.MarkedValues[ix+vNum] = curAbstractValue
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
// The Path parameter enables Path-sensitivity. If Path is "", any Path is accepted and the analysis
// over-approximates.
func (state *IntraAnalysisState) getMarks(i ssa.Instruction, v ssa.Value, path string,
	ignorePath bool) []MarkWithAccessPath {
	var origins []MarkWithAccessPath

	aliasPos, inFunc := state.flowInfo.GetPos(i, v)
	if !inFunc {
		return origins
	}
	abstractVal := state.flowInfo.MarkedValues[aliasPos]
	if abstractVal == nil { // abstractVal should be nil only for non-tracked values
		return origins
	}
	if ignorePath {
		for _, mark := range state.flowInfo.MarkedValues[aliasPos].AllMarks() {
			origins = append(origins, mark)
		}
	} else {
		for _, mark := range state.flowInfo.MarkedValues[aliasPos].MarksAt(path) {
			origins = append(origins, mark)
		}
	}
	return origins
}

// simpleTransfer  propagates all the marks from in to out, ignoring Path and tuple indexes
func simpleTransfer(state *IntraAnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value) {
	transfer(state, loc, in, out, "", NonIndexMark)
}

// transfer propagates all the marks from in to out with the object Path string
// an index >= 0 indicates that element index of the tuple in is accessed
func transfer(state *IntraAnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value, path string, index MarkIndex) {
	transferPre(state, loc, in, out, path, index, false)
}

// transferPre propagates all the marks from in to out with the object Path string
// an index >= 0 indicates that element index of the tuple in is accessed
// a value of true for pre indicates that field-sensitive value a prepended with indexing
func transferPre(state *IntraAnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value, path string,
	index MarkIndex, pre bool) {
	if glob, ok := in.(*ssa.Global); ok {
		state.markValue(loc, out, "", state.flowInfo.GetNewMark(loc.(ssa.Node), Global, glob, index))
	}
	isFieldSensitive := state.flowInfo.pathSensitivityFilter[state.flowInfo.ValueID[out]]
	for _, origin := range state.getMarks(loc, in, path, false) {
		state.flowInfo.SetLoc(origin.Mark, loc)

		if origin.Mark.Index.Kind == NonIndex || index.Kind == NonIndex || index.Value == origin.Mark.Index.Value {
			newPath := origin.AccessPath
			if isFieldSensitive && pre {
				newPath = accessPathPrependIndexing(newPath)
			}
			state.markValue(loc, out, newPath, origin.Mark)
		}
	}

	state.checkFlowIntoGlobal(loc, in, out)
}

// transferCopy propagates the marks for a load, which only requires copying over marks and paths
func transferCopy(t *IntraAnalysisState, loc ssa.Instruction, in ssa.Value, out ssa.Value) {
	pos, ok := t.flowInfo.GetPos(loc, in)
	if !ok {
		return
	}
	// skip constants (constants cannot be marked)
	// if we want to mark constants, this will need to be changed
	if _, isConst := in.(*ssa.Const); isConst {
		return
	}
	aState := t.flowInfo.MarkedValues[pos]
	for _, markWithPath := range aState.AllMarks() {
		t.markValue(loc, out, markWithPath.AccessPath, markWithPath.Mark)
	}
}

// markClosureNode adds a closure node to the graph, and all the related sources and edges.
// The closure Value is tracked like any other Value.
func (state *IntraAnalysisState) markClosureNode(x *ssa.MakeClosure) {
	state.markValue(x, x, "", state.flowInfo.GetNewMark(x, Closure, nil, NonIndexMark))
	for _, boundVar := range x.Bindings {
		mark := state.flowInfo.GetNewMark(x, BoundVar, boundVar, NonIndexMark)
		state.markValue(x, boundVar, "", mark)
	}
}

// callCommonMark can be used for Call and Go instructions that wrap a CallCommon. For a function call, the Value,
// instruction and common are the same object (x = Value = instr and common = x.Common()) but for Go and Defers
// this varies.
func (state *IntraAnalysisState) callCommonMark(value ssa.Value, instr ssa.CallInstruction, common *ssa.CallCommon) {
	// Special case: builtins are handled separately
	if markBuiltinCall(state, value, common, instr) {
		return
	}

	// Mark call, one mark per returned Value
	for _, mark := range state.marksToAdd(value, instr, common) {
		state.markValue(instr, value, mark.AccessPath, mark.Mark)
	}

	args := lang.GetArgs(instr)
	// Iterate over each argument and add edges and marks when necessary
	for _, arg := range args {
		// Mark call argument
		if state.flowInfo.pathSensitivityFilter[state.flowInfo.ValueID[arg]] {
			for _, path := range AccessPathsOfType(arg.Type()) {
				state.flowInfo.AddMark(instr, arg, path,
					state.flowInfo.GetNewLabelledMark(instr.(ssa.Node), CallSiteArg, arg, NonIndexMark, path))
			}
		}
		newMark := state.flowInfo.GetNewMark(instr.(ssa.Node), CallSiteArg, arg, NonIndexMark)
		state.markValue(instr, arg, "", newMark)
	}
}

// marksToAdd returns a slice of marks that will need to be added to track the call information passed as argument.
// Those marks will depend on whether the function is analyzed with field-sensitivity and whether it is a builtin
// or not.
func (state *IntraAnalysisState) marksToAdd(
	value ssa.Value,
	instr ssa.CallInstruction,
	common *ssa.CallCommon) []MarkWithAccessPath {
	res := common.Signature().Results()

	trackingMarks := []MarkWithAccessPath{}
	if res != nil {
		for i := 0; i < res.Len(); i++ {
			if lang.CanType(value) && state.flowInfo.pathSensitivityFilter[state.flowInfo.ValueID[value]] {
				actualType := value.Type()
				switch vt := value.Type().(type) {
				case *types.Tuple:
					if res.Len() > 1 && vt.Len() <= i {
						panic("unexpected malformed result type")
					}
					actualType = vt.At(i).Type()
				}
				for _, path := range AccessPathsOfType(actualType) {
					m := MarkWithAccessPath{
						Mark: state.flowInfo.GetNewLabelledMark(
							instr.(ssa.Node), CallReturn, nil, NewIndex(i), path),
						AccessPath: path,
					}
					trackingMarks = append(trackingMarks, m)
				}
			}
			m := MarkWithAccessPath{
				Mark:       state.flowInfo.GetNewMark(instr.(ssa.Node), CallReturn, nil, NewIndex(i)),
				AccessPath: "",
			}
			trackingMarks = append(trackingMarks, m)
		}
	}
	return trackingMarks
}

// Checking mark flows into specific locations:
// checkCopyIntoArgs checks flows into args/free variables that will be observed by the caller of the function when
// the callee returns
// checkFlowIntoGlobal checks whether the data is flowing into a global location, in which case an edge needs to be
// added.
// TODO: think about moving those functions to the edge building phase

// checkFlowIntoGlobal checks whether the origin is data flowing into a global variable
func (state *IntraAnalysisState) checkFlowIntoGlobal(loc ssa.Instruction, in, out ssa.Value) {
	glob, isGlob := out.(*ssa.Global)
	if !isGlob {
		return
	}
	for _, origin := range state.getMarks(loc, in, "", true) {
		state.summary.addGlobalEdge(origin, nil, loc, glob)
	}
}

// Marking values:
// the functions markValue and markAllAliases are used to mark values. markAllAliases should not be called directly
// unless some special logic is required. markValue will automatically call markAllAliases

// markValue marks the Value v and all values that propagate from v.
// If the Value was not marked, it changes the changeFlag to true to indicate
// that the mark information has changed for the current pass.
//
//gocyclo:ignore
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
		// if the element marked is a slice, then the underlying object needs to be marked
		state.markValue(i, miVal.X, path, mark)
	case *ssa.MakeInterface:
		// if the element marked is an interface, then the original object needs to be marked
		state.markValue(i, miVal.X, path, mark)
	case *ssa.IndexAddr:
		// if the element marked results from indexing some object, then that object is marked with indexing
		state.markValue(i, miVal.X, accessPathPrependIndexing(path), mark)
	case *ssa.Index:
		// if the element marked results from indexing some object, then that object is marked with indexing
		state.markValue(i, miVal.X, accessPathPrependIndexing(path), mark)
	case *ssa.Field:
		// if the element marked results from accessing a field of some object, then that object is marked at that field
		fieldName, isEmbedded := analysisutil.FieldFieldInfo(miVal)
		newAccessPath := accessPathPrependField(path, fieldName, isEmbedded)
		state.markValue(i, miVal.X, newAccessPath, mark)
	case *ssa.FieldAddr:
		// if the element marked results from accessing a field of some object, then that object is marked at that field
		fieldName, isEmbedded := analysisutil.FieldAddrFieldInfo(miVal)
		newAccessPath := accessPathPrependField(path, fieldName, isEmbedded)
		state.markValue(i, miVal.X, newAccessPath, mark)
	case *ssa.UnOp:
		// if the element marked was loaded from a pointer-like object, that pointer-like object is now marked
		if miVal.Op == token.MUL && lang.IsNillableType(miVal.X.Type()) {
			state.markValue(i, miVal.X, path, mark)
		}
	case *ssa.Next:
		// if the element marked is the result of next on an iterator, then the iterator is marked to ensure the mark
		// propagates to the object being iterated on
		if !miVal.IsString {
			state.markValue(i, miVal.Iter, accessPathPrependIndexing(path), mark)
		}
	case *ssa.Range:
		// if the iterator is marked then the underlying map needs to be marked
		state.markValue(i, miVal.X, path, mark)
	case *ssa.Extract:
		// if an extracted object of pointer-like type is marked, then the tuple is marked at that index
		if lang.IsNillableType(miVal.Type()) {
			state.markValue(i, miVal.Tuple, path, mark)
		}
	}

	// Propagate to select referrers if the valye is a true value (i.e. it is not a Call that doesn't return anything)
	_, isCall := v.(*ssa.Call)
	if !isCall || lang.IsValueReturningCall(v) {
		referrers := v.Referrers()
		if referrers != nil {
			for _, referrer := range *referrers {
				state.propagateToReferrer(i, referrer, v, mark, path)
			}
		}
	}
}

// propagateToReferrer propagates the marks to referrer of the value v at instruction ref.
// Instruction i can be different from instruction ref, indicating the mark needs to be propagated at a different
// location in the program.
//
//gocyclo:ignore
func (state *IntraAnalysisState) propagateToReferrer(i ssa.Instruction, ref ssa.Instruction, v ssa.Value, mark *Mark,
	path string) {
	switch referrer := ref.(type) {
	case *ssa.Store:
		if referrer.Val == v && lang.IsNillableType(referrer.Val.Type()) {
			state.markValue(i, referrer.Addr, path, mark)
		}
	case *ssa.IndexAddr:
		// this referrer accesses the marked value's index
		path2, ok := accessPathMatchIndex(path)
		if ok && referrer.X == v {
			state.markValue(i, referrer, path2, mark)
		}
	case *ssa.FieldAddr:
		// this referrer accesses the marked value's field
		fieldName, isEmbedded := analysisutil.FieldAddrFieldInfo(referrer)
		path2 := path
		ok := true
		if !isEmbedded {
			path2, ok = accessPathMatchField(path, fieldName)
		}
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
	case *ssa.Send:
		// the value being marked is sent to a channel somewhere. That channel should be marked.
		if referrer.X == v && lang.IsNillableType(referrer.X.Type()) {
			state.markValue(i, referrer.Chan, path, mark)
		}
	case *ssa.MapUpdate:
		// propagate to map
		if referrer.Value == v && lang.IsNillableType(referrer.Value.Type()) {
			state.markValue(i, referrer.Map, path, mark)
		}
	case *ssa.Next:
		// propagate to iterator
		if !referrer.IsString {
			state.markValue(i, referrer.Iter, path, mark)
		}
	case *ssa.Range:
		// propagate to map
		if referrer.X == v {
			state.markValue(i, referrer.X, path, mark)
		}
	case *ssa.Extract:
		// propagate to tuple
		if referrer.Tuple == v && lang.IsNillableType(referrer.Type()) {
			state.markValue(i, referrer.Tuple, path,
				state.flowInfo.GetNewMark(mark.Node, mark.Type, mark.Qualifier, mark.Index))
		}
	}
}

// findAllPointers returns all the pointers that point to v
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

// getInstr returns the instruction in block number blockNum and instruction instrNum in the block in the function
// being analyzed by the state.
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

// getPointer returns the pointer to x according to the pointer analysis
func (state *IntraAnalysisState) getPointer(x ssa.Value) *pointer.Pointer {
	if ptr, ptrExists := state.parentAnalyzerState.PointerAnalysis.Queries[x]; ptrExists {
		return &ptr
	}
	return nil
}

// getIndirectPointer returns the pointer to x according to the pointer analysis
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
	valueIds func(ssa.Value) (IndexT, bool)) {
	if ptr != nil {
		for _, lb := range ptr.PointsTo().Labels() {
			if lb != nil && lb.Value() != nil && lb.Value().Parent() == f {
				id, ok := valueIds(lb.Value())
				if ok {
					aliases[id][x] = true
				}
			}
		}

		lang.IterateValues(f, func(_ int, v ssa.Value) {
			vid, _ := valueIds(v)
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
func (state *IntraAnalysisState) addParamAliases(p *ssa.Parameter) {
	values := []ssa.Value{p}
	// Find the local copy of the argument, if any
	lang.IterateValues(state.summary.Parent, func(index int, value ssa.Value) {
		if alloc, ok := value.(*ssa.Alloc); ok && alloc.Comment == p.Name() && lang.IsNillableType(alloc.Type()) {
			values = append(values, alloc)
		}
	})
	for _, x := range values {
		state.paramAliases[state.flowInfo.ValueID[x]][p] = true // x is guaranteed to be in flowInfo.ValueID
		addAliases(p, state.summary.Parent, state.getPointer(x),
			state.paramAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueID)
		addAliases(p, state.summary.Parent, state.getIndirectPointer(x),
			state.paramAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueID)
	}
}

// addFreeVarAliases collects information about the Value-aliases of the free variables
func (state *IntraAnalysisState) addFreeVarAliases(v *ssa.FreeVar) {
	values := []ssa.Value{v}
	// Find the local copy of the argument, if any
	lang.IterateValues(state.summary.Parent, func(index int, value ssa.Value) {
		if alloc, ok := value.(*ssa.Alloc); ok && alloc.Comment == v.Name() && lang.IsNillableType(alloc.Type()) {
			values = append(values, alloc)
		}
	})
	for _, x := range values {
		state.freeVarAliases[state.flowInfo.ValueID[x]][v] = true // x is guaranteed to be in flowInfo.ValueID
		addAliases(v, state.summary.Parent, state.getPointer(x),
			state.freeVarAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueID)
		addAliases(v, state.summary.Parent, state.getIndirectPointer(x),
			state.freeVarAliases, state.getPointer, state.getIndirectPointer, state.flowInfo.GetValueID)
	}
}

// FlowInfo returns the flow information of the state
func (state *IntraAnalysisState) FlowInfo() *FlowInformation {
	return state.flowInfo
}

// Block returns the current block of the analyzer state
func (state *IntraAnalysisState) Block() *ssa.BasicBlock {
	return state.curBlock
}
