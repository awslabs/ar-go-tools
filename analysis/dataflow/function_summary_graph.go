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
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	ftu "github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

var allAccessPathFlow = map[string]map[string]bool{"*": {"": true}}

// SummaryGraph is the function dataflow summary graph.
type SummaryGraph struct {
	// the unique ID of the summary
	ID uint32

	// true if summary graph is Constructed, false if it is a dummy
	Constructed bool

	// true if the summary is built from an interface's dataflow contract
	IsInterfaceContract bool

	// true if the summary is pre-summarized
	//
	// pre-summarized summaries are either:
	// - pre-defined in the summaries package, or
	// - loaded from an external summary contract file
	IsPreSummarized bool

	// the ssa function it summarizes
	Parent *ssa.Function

	// the parameters of the function, associated to ParamNode
	Params map[ssa.Node]*ParamNode

	// the free variables of the function, associated to FreeVarNode
	FreeVars map[ssa.Node]*FreeVarNode

	// the call sites of the function
	Callsites map[ssa.CallInstruction]*CallNode

	// the call instructions are linked to CallNode.
	Callees map[ssa.CallInstruction]map[*ssa.Function]*CallNode

	// the builtin calls in the function
	BuiltinCalls map[ssa.CallInstruction]*BuiltinCallNode

	// the MakeClosure nodes in the function  are linked to ClosureNode
	CreatedClosures map[ssa.Instruction]*ClosureNode

	// the MakeClosure nodes referring to this function
	ReferringMakeClosures map[ssa.Instruction]*ClosureNode

	// the synthetic nodes of the function
	SyntheticNodes map[ssa.Instruction]*SyntheticNode

	// the label nodes of the function
	BoundLabelNodes map[ssa.Instruction]map[BindingInfo]*BoundLabelNode

	// the nodes accessing global information
	AccessGlobalNodes map[ssa.Instruction]map[ssa.Value]*AccessGlobalNode

	// the return instructions are linked to ReturnNode, one per Value in a tuple returned
	Returns map[ssa.Instruction][]*ReturnValNode

	// the if statements of the function
	Ifs map[ssa.Instruction]*IfNode

	// errors can be used to accumulate errors that were encountered while building the summary graph
	errors map[error]bool

	// lastNodeID is used to track the number of nodes in the graph
	lastNodeID *uint32

	// Below is some information related to how the summary was built. This allows us to restart building the summary
	// if it has not been constructed.

	// shouldTrack is the function used to identify specific nodes that have been tracked to build that graph.
	shouldTrack func(*State, ssa.Node) bool

	// postBlockCallBack is the function that has been used after a block is completed to adjust the state
	postBlockCallBack func(state *IntraAnalysisState)
}

// NewSummaryGraph builds a new summary graph given a function and its corresponding node.
// Returns a non-nil Value if and only if f is non-nil.
// If s is nil, this will not populate the callees of the summary.
// If non-nil, the returned summary graph is marked as not constructed.
func NewSummaryGraph(s *State, f *ssa.Function, id uint32,
	shouldTrack func(*State, ssa.Node) bool,
	postBlockCallBack func(state *IntraAnalysisState)) *SummaryGraph {
	if s != nil {
		if summary, ok := s.FlowGraph.Summaries[f]; ok {
			return summary
		}
	}

	if f == nil {
		return nil
	}

	var lastNodeID uint32
	lastNodeID = 0

	g := &SummaryGraph{
		ID:                    id,
		Constructed:           false,
		IsInterfaceContract:   false,
		Parent:                f,
		Params:                make(map[ssa.Node]*ParamNode, len(f.Params)),
		FreeVars:              make(map[ssa.Node]*FreeVarNode, len(f.FreeVars)),
		Callees:               make(map[ssa.CallInstruction]map[*ssa.Function]*CallNode),
		Callsites:             make(map[ssa.CallInstruction]*CallNode),
		BuiltinCalls:          make(map[ssa.CallInstruction]*BuiltinCallNode),
		Returns:               make(map[ssa.Instruction][]*ReturnValNode),
		CreatedClosures:       make(map[ssa.Instruction]*ClosureNode),
		ReferringMakeClosures: make(map[ssa.Instruction]*ClosureNode),
		AccessGlobalNodes:     make(map[ssa.Instruction]map[ssa.Value]*AccessGlobalNode),
		SyntheticNodes:        make(map[ssa.Instruction]*SyntheticNode),
		BoundLabelNodes:       make(map[ssa.Instruction]map[BindingInfo]*BoundLabelNode),
		Ifs:                   make(map[ssa.Instruction]*IfNode),
		errors:                map[error]bool{},
		lastNodeID:            &lastNodeID,
		shouldTrack:           shouldTrack,
		postBlockCallBack:     postBlockCallBack,
	}
	// Add the parameters
	for pos, param := range f.Params {
		g.addParam(param, pos)
	}

	// Add the free variables
	for pos, fv := range f.FreeVars {
		g.addFreeVar(fv, pos)
	}

	// Add return instructions
	// A single tuple of return nodes, but it tracks all possible return paths
	n := f.Signature.Results().Len()
	returnNodes := make([]*ReturnValNode, n)
	for i := 0; i < n; i++ {
		returnNodes[i] = &ReturnValNode{parent: g, id: g.newNodeID(), index: i, in: make(map[GraphNode]EdgeInfo)}
	}

	// Adding return nodes
	for _, block := range f.Blocks {
		last := lang.LastInstr(block)
		if last != nil {
			retInstr, isReturn := last.(*ssa.Return)
			if isReturn {
				for i := range retInstr.Results {
					g.addReturn(retInstr, returnNodes[i])
				}
			}
		}
	}
	// When the function is external, we need to add a dummy return node
	if lang.IsExternal(g.Parent) {
		for i := 0; i < n; i++ {
			g.addReturn(nil, returnNodes[i])
		}
	}

	g.initializeInnerNodes(s, shouldTrack)

	return g
}

func (g *SummaryGraph) newNodeID() uint32 {
	return atomic.AddUint32(g.lastNodeID, 1)
}

func (g *SummaryGraph) initializeInnerNodes(s *State,
	shouldTrack func(*State, ssa.Node) bool) {
	// Add all call instructions
	lang.IterateInstructions(g.Parent, func(_ int, instruction ssa.Instruction) {
		switch x := instruction.(type) {
		case ssa.CallInstruction:
			if s != nil {
				if isHandledBuiltinCall(x) {
					g.addBuiltinCallInstr(x)
				} else {
					g.addCallInstr(s, x)
				}
			}
		case *ssa.MakeClosure:
			g.addClosure(x)
		case *ssa.If:
			g.addIfNode(x)

		// Other types of sources that may be used in config
		case *ssa.Alloc, *ssa.FieldAddr, *ssa.Field, *ssa.UnOp, *ssa.Store:
			if shouldTrack != nil && shouldTrack(s, x.(ssa.Node)) {
				// TODO: for debugging, shouldTrack could return the label to associate to the node
				// instead of just a boolean.
				g.addSyntheticNode(x, "synthetic")
			}
		}
	})

	// Add global nodes if the state is non-nil
	if s != nil {
		lang.IterateInstructions(g.Parent,
			func(_ int, i ssa.Instruction) {
				var operands []*ssa.Value
				operands = i.Operands(operands)
				for _, operand := range operands {
					// Add marks for globals
					if glob, ok := (*operand).(*ssa.Global); ok {
						if node, ok := s.Globals[glob]; ok {
							g.AddAccessGlobalNode(i, node)
						}
					}
				}
			})
	}
}

// ReturnType returns the return type of the function summarized
func (g *SummaryGraph) ReturnType() *types.Tuple {
	if sig, ok := g.Parent.Type().Underlying().(*types.Signature); ok {
		return sig.Results()
	}
	return nil
}

// SyncGlobals must be executed after the summary is built in order to synchronize the information between the
// global access node (write or read to a global in the function) and the GlobalNode that tracks the information
// about read and write locations of that global.
func (g *SummaryGraph) SyncGlobals() {
	for _, nodeSet := range g.AccessGlobalNodes {
		for _, node := range nodeSet {
			if node.IsWrite {
				node.Global.addWriteLoc(node)
			} else if len(node.out) > 0 {
				node.Global.addReadLoc(node)
			}
		}
	}
}

// addError adds an error to the summary graph. Can be modified to change the behavior when an error is encountered
// when building the summary
func (g *SummaryGraph) addError(e error) {
	g.errors[e] = true
}

// ShowAndClearErrors writes the errors in the graph to the writer and clears them
func (g *SummaryGraph) ShowAndClearErrors(w io.Writer) {
	for err := range g.errors {
		w.Write([]byte(err.Error() + "\n"))
	}
	g.errors = map[error]bool{}
}

// Functions to add nodes to the graph

// addParam adds a parameter to the summary
// @requires g != nil
func (g *SummaryGraph) addParam(param *ssa.Parameter, pos int) {
	if param == nil {
		return
	}

	g.Params[param] = &ParamNode{
		id:      g.newNodeID(),
		parent:  g,
		ssaNode: param,
		out:     make(map[GraphNode][]EdgeInfo),
		in:      make(map[GraphNode]EdgeInfo),
		argPos:  pos,
	}
}

// addFreeVar adds a free variable to the summary
// @requires g != nil
func (g *SummaryGraph) addFreeVar(fv *ssa.FreeVar, pos int) {
	if fv == nil {
		return
	}

	g.FreeVars[fv] = &FreeVarNode{
		id:      g.newNodeID(),
		parent:  g,
		ssaNode: fv,
		out:     make(map[GraphNode][]EdgeInfo),
		in:      make(map[GraphNode]EdgeInfo),
		fvPos:   pos,
	}
}

// addCallNode adds a call site to the summary
func (g *SummaryGraph) addCallNode(node *CallNode) bool {
	if node == nil {
		return false
	}
	if _, ok := g.Callees[node.callSite]; ok {
		g.Callees[node.callSite][node.Callee()] = node
	} else {
		g.Callees[node.callSite] = map[*ssa.Function]*CallNode{node.Callee(): node}
	}
	return true
}

// addCallInstr adds a call site to the summary from a call instruction (use when no call graph is available)
// @requires g != nil
func (g *SummaryGraph) addCallInstr(c *State, instr ssa.CallInstruction) {
	// Already seen this instruction? Multiple calls of this function will not gather more information.
	if _, ok := g.Callees[instr]; ok {
		return
	}

	args := lang.GetArgs(instr)
	callees, err := c.ResolveCallee(instr, true)
	if err != nil {
		c.Logger.Errorf("missing information in state (%s), could not resolve callee in instruction %s", err,
			ftu.Sanitize(instr.String()))
		panic("critical information missing in analysis")
	}

	if c.Logger.LogsDebug() && instr.Common().IsInvoke() && len(callees) > 10 {
		interfaceMethod := lang.InstrMethodKey(instr)
		c.Logger.Debugf("%d callees for method %s in %s. Consider using a dataflow contract to minimize state explosion",
			len(callees),
			interfaceMethod.ValueOr(""), ftu.SanitizeRepr(instr))
	}

	// Add each callee as a node for this call instruction
	for _, callee := range callees {
		node := &CallNode{
			id:       g.newNodeID(),
			parent:   g,
			callee:   callee,
			args:     make([]*CallNodeArg, len(args)),
			callSite: instr,
			out:      make(map[GraphNode][]EdgeInfo),
			in:       make(map[GraphNode]EdgeInfo),
		}

		for pos, arg := range args {
			argNode := &CallNodeArg{
				id:       g.newNodeID(),
				parent:   node,
				ssaValue: arg,
				argPos:   pos,
				out:      make(map[GraphNode][]EdgeInfo),
				in:       make(map[GraphNode]EdgeInfo),
			}
			node.args[pos] = argNode
		}
		g.addCallNode(node)
	}
}

// addCallInstr adds a call site to the summary from a call instruction (use when no call graph is available)
// @requires g != nil
func (g *SummaryGraph) addBuiltinCallInstr(instr ssa.CallInstruction) {
	// Already seen this instruction? Multiple calls of this function will not gather more information.
	if _, ok := g.Callees[instr]; ok {
		return
	}

	//_args := lang.GetArgs(instr)

	node := &BuiltinCallNode{
		id:       g.newNodeID(),
		parent:   g,
		callSite: instr,
		name:     instr.Common().Value.Name(),
		out:      make(map[GraphNode][]EdgeInfo),
		in:       make(map[GraphNode]EdgeInfo),
		marks:    nil,
	}
	// Add each callee as a node for this call instruction
	g.BuiltinCalls[instr] = node
}

// addReturn adds a return node to the summary
// @requires g != nil
func (g *SummaryGraph) addReturn(instr ssa.Instruction, node *ReturnValNode) {
	n := g.Parent.Signature.Results().Len()
	// No Value is returned
	if n <= 0 {
		return
	}
	if _, ok := g.Returns[instr]; !ok {
		g.Returns[instr] = make([]*ReturnValNode, n)
	}
	g.Returns[instr][node.index] = node
}

// addClosure adds a closure node to the summary
// @requires g != nil
func (g *SummaryGraph) addClosure(x *ssa.MakeClosure) {
	if _, ok := g.CreatedClosures[x]; ok {
		return
	}

	node := &ClosureNode{
		id:             g.newNodeID(),
		parent:         g,
		ClosureSummary: nil,
		instr:          x,
		boundVars:      []*BoundVarNode{},
		out:            make(map[GraphNode][]EdgeInfo),
		in:             make(map[GraphNode]EdgeInfo),
	}

	g.CreatedClosures[x] = node

	for pos, binding := range x.Bindings {
		bindingNode := &BoundVarNode{
			id:       g.newNodeID(),
			parent:   node,
			ssaValue: binding,
			bPos:     pos,
			out:      make(map[GraphNode][]EdgeInfo),
			in:       make(map[GraphNode]EdgeInfo),
		}
		node.boundVars = append(node.boundVars, bindingNode)
	}
}

// AddAccessGlobalNode adds a global node at instruction instr (the location) accessing the global (the package-level
// global variable). This does not modify the GlobalNode
func (g *SummaryGraph) AddAccessGlobalNode(instr ssa.Instruction, global *GlobalNode) {
	if _, ok := g.AccessGlobalNodes[instr]; !ok {
		g.AccessGlobalNodes[instr] = map[ssa.Value]*AccessGlobalNode{}
	}
	if _, ok := g.AccessGlobalNodes[instr][global.value]; !ok {
		node := &AccessGlobalNode{
			id:      g.newNodeID(),
			IsWrite: false,
			graph:   g,
			instr:   instr,
			Global:  global,
			out:     make(map[GraphNode][]EdgeInfo),
			in:      make(map[GraphNode]EdgeInfo),
		}
		g.AccessGlobalNodes[instr][global.value] = node
	}
}

// addSyntheticNode adds a synthetic node to the summary. instr will be the instruction of the synthetic node, and
// label will be its label. The node is created only if the instruction is not present in the g.syntheticNodes map.
// If a node is created, then g.syntheticNodes[instr] will be the node created.
// @requires g != nil
func (g *SummaryGraph) addSyntheticNode(instr ssa.Instruction, label string) {
	if _, ok := g.SyntheticNodes[instr]; !ok {
		node := &SyntheticNode{
			id:     g.newNodeID(),
			parent: g,
			instr:  instr,
			label:  label,
			out:    make(map[GraphNode][]EdgeInfo),
			in:     make(map[GraphNode]EdgeInfo),
		}
		g.SyntheticNodes[instr] = node
	}
}

func (g *SummaryGraph) addBoundLabelNode(instr ssa.Instruction, label *pointer.Label, target BindingInfo) {
	instrAndTargetExists := false
	if instrEntry, instrExists := g.BoundLabelNodes[instr]; instrExists {
		_, instrAndTargetExists = instrEntry[target]
	} else {
		g.BoundLabelNodes[instr] = make(map[BindingInfo]*BoundLabelNode)
	}

	if !instrAndTargetExists {
		node := &BoundLabelNode{
			id:         g.newNodeID(),
			parent:     g,
			instr:      instr,
			label:      label,
			targetInfo: target,
			out:        make(map[GraphNode][]EdgeInfo),
			in:         make(map[GraphNode]EdgeInfo),
		}

		g.BoundLabelNodes[instr][target] = node
	}
}

func (g *SummaryGraph) addIfNode(x *ssa.If) {
	if _, ok := g.Ifs[x]; !ok {
		node := &IfNode{
			id:      g.newNodeID(),
			parent:  g,
			ssaNode: x,
			out:     make(map[GraphNode][]EdgeInfo),
			in:      make(map[GraphNode]EdgeInfo),
		}
		g.Ifs[x] = node
	}
}

func (g *SummaryGraph) addSyntheticEdge(mark MarkWithAccessPath, info *ConditionInfo, instr ssa.Instruction, _ string) {

	node, ok := g.SyntheticNodes[instr]
	if !ok {
		return
	}
	g.addEdge(mark, node, info)
}

func (g *SummaryGraph) addBoundLabelEdge(mark MarkWithAccessPath, info *ConditionInfo,
	instr ssa.Instruction) {
	nodes, ok := g.BoundLabelNodes[instr]
	if !ok {
		return
	}
	for _, node := range nodes {
		g.addEdge(mark, node, info)
	}
}

func (g *SummaryGraph) addIfEdge(mark MarkWithAccessPath, info *ConditionInfo, n *ssa.If) {
	node, ok := g.Ifs[n]
	if !ok {
		return
	}
	g.addEdge(mark, node, info)
}

// selectNodesFromMark returns a slice of nodes that correspond to the mark. In most cases this slice should have only
// one element.
//
//gocyclo:ignore
func (g *SummaryGraph) selectNodesFromMark(m Mark) []GraphNode {
	var nodes []GraphNode

	if m.IsParameter() {
		if argNode, ok := g.Params[m.Node]; ok {
			nodes = append(nodes, argNode)
		}
	}

	if m.IsCallSiteArg() {
		// A CallSite source node must be a CallInstruction
		sourceCallInstr := m.Node.(ssa.CallInstruction)
		// and it must have a qualifier representing the argument
		if callNodes, ok := g.Callees[sourceCallInstr]; ok {
			for _, callNode := range callNodes {
				argNode := callNode.FindArg(m.Qualifier)
				if argNode != nil {
					nodes = append(nodes, argNode)
				}
			}
		}
	}

	if m.IsCallReturn() {
		// A CallReturn source node must be a CallInstruction
		callInstruction := m.Node.(ssa.CallInstruction)
		if callNodes, ok := g.Callees[callInstruction]; ok {
			for _, callNode := range callNodes {
				nodes = append(nodes, callNode)
			}
		}
		// Can also be a builtin call node
		if builtinCallNode, ok := g.BuiltinCalls[callInstruction]; ok {
			nodes = append(nodes, builtinCallNode)
		}
	}

	if m.IsFreeVar() {
		if freeVarNode, ok := g.FreeVars[m.Node]; ok {
			nodes = append(nodes, freeVarNode)
		}
	}

	if m.IsBoundVar() {
		// A bound var source's node must be a make closure node
		closureInstruction := m.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[closureInstruction]; ok {
			bvNode := cNode.FindBoundVar(m.Qualifier)
			if bvNode != nil {
				nodes = append(nodes, bvNode)
			}
		}
	}

	if m.IsClosure() {
		closureInstruction := m.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[closureInstruction]; ok {
			nodes = append(nodes, cNode)
		}
	}

	if m.IsSynthetic() {
		// A synthetic source can refer to any instruction
		synthetic := m.Node.(ssa.Instruction)
		if syntheticNode, ok := g.SyntheticNodes[synthetic]; ok {
			nodes = append(nodes, syntheticNode)
		}
	}

	if m.IsGlobal() {
		globalAccessInstruction := m.Node.(ssa.Instruction)
		if group, ok := g.AccessGlobalNodes[globalAccessInstruction]; ok {
			if globalNode, ok := group[m.Qualifier]; ok {
				nodes = append(nodes, globalNode)
			}
		}
	}

	return nodes
}

// Functions to add edges to the graph

// addEdge adds an edge between source and targetInfo in the summary graph g.
// @requires g != nil
//
//gocyclo:ignore
func (g *SummaryGraph) addEdge(source MarkWithAccessPath, dest GraphNode, cond *ConditionInfo) {
	// This function's goal is to define how the source of an edge is obtained in the summary given a Mark that
	// is produced in the intra-procedural analysis.

	if source.Mark.IsParameter() {
		if sourceArgNode, ok := g.Params[source.Mark.Node]; ok && isDiffNode(source, sourceArgNode, dest) {
			updateEdgeInfo(source, dest, cond, sourceArgNode)
		}
	}

	if source.Mark.IsCallSiteArg() {
		// A CallSite source node must be a CallInstruction
		sourceCallInstr := source.Mark.Node.(ssa.CallInstruction)
		// and it must have a qualifier representing the argument
		if sourceNodes, ok := g.Callees[sourceCallInstr]; ok {
			for _, sourceNode := range sourceNodes {
				sourceCallArgNode := sourceNode.FindArg(source.Mark.Qualifier)
				if sourceCallArgNode != nil && sourceCallArgNode != dest {
					updateEdgeInfo(source, dest, cond, sourceCallArgNode)
				}
			}
		}
	}

	if source.Mark.IsCallReturn() {
		// A CallReturn source node must be a CallInstruction
		sourceCallInstr := source.Mark.Node.(ssa.CallInstruction)
		// either a call node
		if sourceNodes, ok := g.Callees[sourceCallInstr]; ok {
			for _, sourceNode := range sourceNodes {
				if sourceNode != dest {
					updateEdgeInfo(source, dest, cond, sourceNode)
				}
			}
		}
		// or a builtin call node
		if builtinCallNode, ok := g.BuiltinCalls[sourceCallInstr]; ok {
			if builtinCallNode != dest {
				updateEdgeInfo(source, dest, cond, builtinCallNode)
			}
		}
	}

	if source.Mark.IsFreeVar() {
		if sourceFreeVarNode, ok := g.FreeVars[source.Mark.Node]; ok && isDiffNode(source, sourceFreeVarNode, dest) {
			updateEdgeInfo(source, dest, cond, sourceFreeVarNode)
		}
	}

	if source.Mark.IsBoundVar() {
		// A bound var source's node must be a make closure node
		sourceClosure := source.Mark.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[sourceClosure]; ok {
			bvNode := cNode.FindBoundVar(source.Mark.Qualifier)
			if bvNode != nil && bvNode != dest {
				updateEdgeInfo(source, dest, cond, bvNode)
			}
		}
	}

	if source.Mark.IsClosure() {
		sourceClosure := source.Mark.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[sourceClosure]; ok {
			if cNode != dest {
				updateEdgeInfo(source, dest, cond, cNode)
			}
		}
	}

	if source.Mark.IsSynthetic() {
		// A synthetic source can refer to any instruction
		sourceInstr := source.Mark.Node.(ssa.Instruction)
		if sourceNode, ok := g.SyntheticNodes[sourceInstr]; ok {
			if sourceNode != dest {
				updateEdgeInfo(source, dest, cond, sourceNode)
			}
		}
	}

	if source.Mark.IsGlobal() {
		sourceInstr := source.Mark.Node.(ssa.Instruction)
		if group, ok := g.AccessGlobalNodes[sourceInstr]; ok {
			if sourceNode, ok := group[source.Mark.Qualifier]; ok {
				updateEdgeInfo(source, dest, cond, sourceNode)
			}
		}
	}

	if source.Mark.IsIf() {
		sourceInstr := source.Mark.Node.(ssa.Instruction)
		if sourceNode, ok := g.Ifs[sourceInstr]; ok {
			if sourceNode != dest {
				updateEdgeInfo(source, dest, cond, sourceNode)
			}
		}
	}
}

func isDiffNode(mark MarkWithAccessPath, source GraphNode, dest GraphNode) bool {
	return source != dest || mark.Mark.Label != mark.AccessPath
}

func updateEdgeInfo(source MarkWithAccessPath, dest GraphNode, info *ConditionInfo, sourceNode GraphNode) {
	outMap := sourceNode.Out()
	relPath := map[string]map[string]bool{source.Mark.Label: {source.AccessPath: true}}
	edgeInfos, destPresent := outMap[dest]
	if !destPresent {
		edgeInfos = make([]EdgeInfo, 0, 1)
	}
	edgeInfoFound := false
	for _, edgeInfo := range edgeInfos {
		// add the access path to each edge with matching index
		if edgeInfo.Index == source.Mark.Index.Value {
			edgeInfoFound = true
			if _, ok := edgeInfo.RelPath[source.Mark.Label]; ok {
				edgeInfo.RelPath[source.Mark.Label][source.AccessPath] = true
			} else {
				edgeInfo.RelPath[source.Mark.Label] = map[string]bool{source.AccessPath: true}
			}
		}
	}
	if !edgeInfoFound {
		outMap[dest] = append(edgeInfos, EdgeInfo{relPath, source.Mark.Index.Value, info})
	}

	addInEdge(dest, sourceNode, EdgeInfo{relPath, source.Mark.Index.Value, info})
}

// addCallArgEdge adds an edge in the summary from a mark to a function call argument.
// @requires g != nil
func (g *SummaryGraph) addCallArgEdge(mark MarkWithAccessPath, cond *ConditionInfo, call ssa.CallInstruction,
	arg ssa.Value) {
	callNodes := g.Callees[call]
	if callNodes == nil {
		return
	}

	for _, callNode := range callNodes {
		callNodeArg := callNode.FindArg(arg)
		if callNodeArg == nil {
			panic("attempting to set call arg edge but no call arg node")
		}
		g.addEdge(mark, callNodeArg, cond)
	}
}

// addCallEdge adds an edge that flows to a call node.
func (g *SummaryGraph) addCallEdge(mark MarkWithAccessPath, cond *ConditionInfo, call ssa.CallInstruction) {

	callNodes := g.Callees[call]
	if callNodes == nil {
		return
	}
	for _, callNode := range callNodes {
		g.addEdge(mark, callNode, cond)
	}
}

func (g *SummaryGraph) addBuiltinCallEdge(mark MarkWithAccessPath, call ssa.CallInstruction, cond *ConditionInfo) {
	builtinNode := g.BuiltinCalls[call]
	if builtinNode == nil {
		return
	}
	g.addEdge(mark, builtinNode, cond)
}

// addBoundVarEdge adds an edge in the summary from a mark to a function call argument.
// @requires g != nil
func (g *SummaryGraph) addBoundVarEdge(mark MarkWithAccessPath, cond *ConditionInfo, closure *ssa.MakeClosure,
	v ssa.Value) {

	closureNode := g.CreatedClosures[closure]
	if closureNode == nil {
		g.addError(fmt.Errorf("attempting to set bound arg edge but no closure node for %s", closure))
		return
	}

	boundVarNode := closureNode.FindBoundVar(v)
	if boundVarNode == nil {
		g.addError(fmt.Errorf("attempting to set bound var edge but no bound var node"))
		return
	}
	g.addEdge(mark, boundVarNode, cond)

}

// addReturnEdge adds an edge in the summary from the mark to a return instruction
// @requires g != nil
func (g *SummaryGraph) addReturnEdge(mark MarkWithAccessPath, cond *ConditionInfo, retInstr ssa.Instruction,
	tupleIndex int) {

	if tupleIndex < 0 || tupleIndex > len(g.Returns) {
		return
	}

	retNode := g.Returns[retInstr][tupleIndex]

	if retNode == nil {
		g.addError(fmt.Errorf("attempting to set return edge but no return node"))
		return
	}

	g.addEdge(mark, retNode, cond)
}

// addParamEdge adds an edge in the summary from the mark to a parameter of the function
func (g *SummaryGraph) addParamEdge(mark MarkWithAccessPath, cond *ConditionInfo, param ssa.Node) {
	paramNode := g.Params[param]

	if paramNode == nil {
		g.addError(fmt.Errorf("attempting to set param edge but no param node"))
	}

	g.addEdge(mark, paramNode, cond)
}

// addGlobalEdge adds an edge from a mark to a GlobalNode
func (g *SummaryGraph) addGlobalEdge(mark MarkWithAccessPath, cond *ConditionInfo, loc ssa.Instruction, v *ssa.Global) {

	node := g.AccessGlobalNodes[loc][v]

	if node == nil {
		// TODO: debug this
		//g.addError(fmt.Errorf("attempting to set global edge but no global node"))
		return
	}
	// Set node to written
	node.IsWrite = true
	g.addEdge(mark, node, cond)
}

// addFreeVarEdge adds an edge in the summary from the mark to a bound variable of a closure
func (g *SummaryGraph) addFreeVarEdge(mark MarkWithAccessPath, cond *ConditionInfo, freeVar ssa.Node) {
	freeVarNode := g.FreeVars[freeVar]
	if freeVarNode == nil {
		g.addError(fmt.Errorf("attempting to set free var edge but no free var node"))
	}
	g.addEdge(mark, freeVarNode, cond)
}

//gocyclo:ignore
func addInEdge(dest GraphNode, source GraphNode, path EdgeInfo) {
	switch node := dest.(type) {
	case *ParamNode:
		node.in[source] = path
	case *CallNode:
		node.in[source] = path
	case *CallNodeArg:
		node.in[source] = path
	case *FreeVarNode:
		node.in[source] = path
	case *ReturnValNode:
		node.in[source] = path
	case *ClosureNode:
		node.in[source] = path
	case *SyntheticNode:
		node.in[source] = path
	case *AccessGlobalNode:
		node.in[source] = path
	case *BoundVarNode:
		node.in[source] = path
	case *BoundLabelNode:
		node.in[source] = path
	case *IfNode:
		node.in[source] = path
	case *BuiltinCallNode:
		node.in[source] = path

	default:
		panic(fmt.Sprintf("invalid dest node type: %T", dest))
	}
}

// Loading function summaries from predefined summaries

// addParamEdgeByPos adds an edge between the arguments at position src and targetInfo in the summary graph.
// Returns true if it successfully added an edge.
// Returns false if it failed to add an edge because it could not fetch the required data (the positions might not be
// correct)
func (g *SummaryGraph) addParamEdgeByPos(src int, dest int) bool {
	n := len(g.Parent.Params)
	if src < 0 || src >= n || dest < 0 || dest >= n {
		return false
	}
	srcNode := g.Parent.Params[src]
	destNode := g.Parent.Params[dest]

	if srcNode == nil || destNode == nil {
		return false
	}

	if srcArg, ok := g.Params[srcNode]; ok {
		if destArg, ok := g.Params[destNode]; ok {
			outEdges := srcArg.out[destArg]
			if outEdges == nil {
				outEdges = make([]EdgeInfo, 0, 1)
			}
			srcArg.out[destArg] = append(outEdges, EdgeInfo{allAccessPathFlow, 0, nil})

			if destArg.in == nil {
				destArg.in = make(map[GraphNode]EdgeInfo)
			}
			destArg.in[srcArg] = EdgeInfo{allAccessPathFlow, 0, nil}
			return true
		}
	}
	return false
}

// addReturnEdgeByPos adds an edge between the parameter at position src to the returned tuple position targetInfo.
func (g *SummaryGraph) addReturnEdgeByPos(src int, pos int) bool {
	if src < 0 || src >= len(g.Parent.Params) || pos < 0 {
		return false
	}
	srcNode := g.Parent.Params[src]
	if srcNode == nil {
		return false
	}

	if srcArg, ok := g.Params[srcNode]; ok {
		// Add edge to any return
		for _, retNode := range g.Returns {
			if pos >= len(retNode) || retNode[pos] == nil {
				continue
			}

			outEdges := srcArg.out[retNode[pos]]
			if outEdges == nil {
				outEdges = make([]EdgeInfo, 0, 1)
			}
			srcArg.out[retNode[pos]] = append(outEdges, EdgeInfo{allAccessPathFlow, pos, nil})

			if retNode[pos].in == nil {
				retNode[pos].in = make(map[GraphNode]EdgeInfo)
			}
			retNode[pos].in[srcArg] = EdgeInfo{allAccessPathFlow, pos, nil}
			return true
		}
	}
	return false
}

// NewPredefinedSummary searches for a summary for f in the summaries packages and builds the SummaryGraph it
// represents. The resulting summary will only contain parameter and return nodes and edges between those. It will
// not include any call node or call argument nodes.
//
// If f is nil, or f has no predefined summary, then the function returns nil.
// If f has a predefined summary, then the returned summary graph is marked as constructed.
// cg can be nil.
func NewPredefinedSummary(f *ssa.Function, id uint32) *SummaryGraph {
	preDef, ok := summaries.SummaryOfFunc(f)
	if !ok {
		return nil
	}
	summaryBase := NewSummaryGraph(nil, f, id, nil, nil)
	if summaryBase == nil {
		return nil
	}
	summaryBase.PopulateGraphFromSummary(preDef, false)
	return summaryBase
}

// PopulateGraphFromSummary populates the summary from a predefined summary provided as argument.
// isInterface indicates whether this predefined summary comes from an interface contract.
func (g *SummaryGraph) PopulateGraphFromSummary(summary summaries.Summary, isInterface bool) {
	if g == nil {
		return
	}

	// Add edges from parameter to parameter
	for srcArg, destArgs := range summary.Args {
		for _, destArg := range destArgs {
			g.addParamEdgeByPos(srcArg, destArg)
		}
	}
	// Add edges from parameter to return instruction
	for srcArg, retArray := range summary.Rets {
		for _, retIndex := range retArray {
			g.addReturnEdgeByPos(srcArg, retIndex)
		}
	}
	// clean callees for a predefined summary
	g.Callees = map[ssa.CallInstruction]map[*ssa.Function]*CallNode{}
	// a summary graph loaded from a predefined summary is marked as constructed.
	g.Constructed = true
	// the isInterface parameter determines if this represents the summary from an interface dataflow contract
	g.IsInterfaceContract = isInterface

	g.IsPreSummarized = true
}

// Utilities for printing graphs

func (a *ParamNode) String() string {
	if a == nil {
		return ""
	}
	fname := ""
	if a.parent.Parent != nil {
		fname = ftu.Sanitize(a.parent.Parent.Name())
	}
	return fmt.Sprintf("\"[#%d.%d] %s of %s [%d]\"",
		a.parent.ID, a.ID(), ftu.SanitizeRepr(a.SsaNode()), fname, a.Index())
}

func (a *CallNodeArg) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] @arg %d:%s in %s \"",
		a.ParentNode().parent.ID, a.ID(), a.Index(), ftu.SanitizeRepr(a.ssaValue),
		strings.Trim(a.ParentNode().String(), "\""))
}

func (a *CallNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] (%s)call: %s in %s\"",
		a.parent.ID, a.id, a.callee.Type.Code(),
		ftu.SanitizeRepr(a.callSite),
		ftu.Sanitize(a.callSite.Parent().Name()))
}

func (a *ReturnValNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] %s.return.%d\"", a.parent.ID, a.id,
		ftu.Sanitize(a.parent.Parent.Name()), a.index)
}

func (a *SyntheticNode) String() string {
	if a == nil {
		return ""
	}
	if _, isSsaValue := a.instr.(ssa.Value); isSsaValue {
		return fmt.Sprintf("\"[#%d.%d] synthetic: %s = %s\"",
			a.parent.ID, a.id, ftu.Sanitize(a.instr.(ssa.Value).Name()), ftu.SanitizeRepr(a.instr))
	}
	return fmt.Sprintf("\"[#%d.%d] synthetic: %s\"",
		a.parent.ID, a.id, ftu.SanitizeRepr(a.instr))
}

func (a *FreeVarNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] freevar:%s\"", a.parent.ID, a.id, ftu.Sanitize(a.ssaNode.Name()))
}

func (a *BoundVarNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] boundvar:%s\"", a.ParentNode().parent.ID, a.id, ftu.SanitizeRepr(a.ssaValue))
}

func (a *ClosureNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] closure:%s\"", a.parent.ID, a.id, ftu.SanitizeRepr(a.instr))
}

func (a *AccessGlobalNode) String() string {
	if a == nil {
		return ""
	}
	typ := "read"
	if a.IsWrite {
		typ = "write"
	}
	return fmt.Sprintf("\"[#%d.%d] global:%s in %s (%s)\"",
		a.graph.ID, a.id, ftu.SanitizeRepr(a.Global.value), ftu.SanitizeRepr(a.instr), typ)
}

func (a *BoundLabelNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] bound: %s to %s #%d\"", a.parent.ID, a.id,
		ftu.SanitizeRepr(a.instr),
		ftu.SanitizeRepr(a.targetInfo.MakeClosure),
		a.targetInfo.BoundIndex)
}

func (b *BuiltinCallNode) String() string {
	if b == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] builtin:%s\"", b.parent.ID, b.id, b.name)
}

func (a *IfNode) String() string {
	if a == nil {
		return ""
	}

	return fmt.Sprintf("\"[#%d] %s\"", a.id, ftu.SanitizeRepr(a.ssaNode))
}

// Print the summary graph to w in the graphviz format.
// If g is nil, then prints the empty graph "subgraph {}"
//
//gocyclo:ignore
func (g *SummaryGraph) Print(outEdgesOnly bool, w io.Writer) {
	if g == nil || g.Parent == nil {
		fmt.Fprintf(w, "subgraph {}\n")
		return
	}
	fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", ftu.Sanitize(g.Parent.Name()))
	fmt.Fprintf(w, "\tlabel=\"%s\";\n", g.Parent.Name()) // label each subgraph with the function name
	for _, a := range g.Params {
		for n := range a.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(a.String()), escapeString(n.String()))
		}
		if !outEdgesOnly {
			for n := range a.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(a.String()), escapeString(n.String()))
			}
		}
	}

	for _, a := range g.FreeVars {
		for n := range a.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(a.String()), escapeString(n.String()))
		}
		if !outEdgesOnly {
			for n := range a.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(a.String()), escapeString(n.String()))
			}
		}
	}

	for _, callNodes := range g.Callees {
		for _, callN := range callNodes {
			for n, edgeInfos := range callN.Out() {
				for _, obj := range edgeInfos {
					fmt.Fprintf(w, "\t%s.%d -> %s;\n", escapeString(callN.String()), obj.Index, escapeString(n.String()))
				}
			}
			if !outEdgesOnly {
				for n := range callN.In() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(callN.String()), escapeString(n.String()))
				}
			}
			for _, x := range callN.args {
				for n := range x.Out() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(x.String()), escapeString(n.String()))
				}
				if !outEdgesOnly {
					for n := range x.In() {
						fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(x.String()), escapeString(n.String()))
					}
				}
			}
		}
	}

	for _, closure := range g.CreatedClosures {
		for _, boundvar := range closure.boundVars {
			for n := range boundvar.Out() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(boundvar.String()), escapeString(n.String()))
			}
			if !outEdgesOnly {
				for n := range boundvar.In() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(boundvar.String()), escapeString(n.String()))
				}
			}
		}
		for o := range closure.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(closure.String()), escapeString(o.String()))
		}
		if !outEdgesOnly {
			for i := range closure.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(closure.String()), escapeString(i.String()))
			}
		}
	}

	for _, retTuple := range g.Returns {
		for _, r := range retTuple {
			// a return node can be nil if its Value is constant
			if r == nil {
				continue
			}
			for n, edgeInfos := range r.Out() {
				for _, obj := range edgeInfos {
					fmt.Fprintf(w, "\t%s.%d -> %s;\n", escapeString(r.String()), obj.Index, escapeString(n.String()))
				}
			}
			if !outEdgesOnly {
				for n, obj := range r.In() {
					fmt.Fprintf(w, "\t%s.%d -> %s;\n", escapeString(r.String()), obj.Index, escapeString(n.String()))
				}
			}
		}
	}

	for _, s := range g.SyntheticNodes {
		for n := range s.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(s.String()), escapeString(n.String()))
		}
		if !outEdgesOnly {
			for n := range s.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(s.String()), escapeString(n.String()))
			}
		}
	}

	for _, group := range g.BoundLabelNodes {
		for _, s := range group {
			for n := range s.Out() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(s.String()), escapeString(n.String()))
			}
			if !outEdgesOnly {
				for n := range s.In() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(s.String()), escapeString(n.String()))
				}
			}
		}
	}

	for _, group := range g.AccessGlobalNodes {
		for _, s := range group {
			for n := range s.Out() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(s.String()), escapeString(n.String()))
			}
			if !outEdgesOnly {
				for n := range s.In() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(s.String()), escapeString(n.String()))
				}
			}
		}
	}

	for _, builtinCall := range g.BuiltinCalls {
		for n := range builtinCall.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(builtinCall.String()), escapeString(n.String()))
		}
		if !outEdgesOnly {
			for n := range builtinCall.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escapeString(builtinCall.String()), escapeString(n.String()))
			}
		}
	}

	fmt.Fprint(w, "}\n")
}

// PrettyPrint prints the summary graph to w in a readable format.
//
//gocyclo:ignore
func (g *SummaryGraph) PrettyPrint(outEdgesOnly bool, w io.Writer) {
	if g == nil || g.Parent == nil {
		fmt.Fprintf(w, "Empty graph!\n")
		return
	}
	fmt.Fprintf(w, "%s %s:\n", ftu.Yellow("Summary of"), ftu.Italic(ftu.Purple(g.Parent.Name())))
	for _, a := range g.Params {
		ppNodes("Parameter", w, a, outEdgesOnly)
	}

	for _, a := range g.FreeVars {
		ppNodes("Free var", w, a, outEdgesOnly)
	}

	for _, callNodes := range g.Callees {
		for _, callN := range callNodes {
			ppNodes("Call", w, callN, outEdgesOnly)
			for _, x := range callN.args {
				ppNodes("Call arg", w, x, outEdgesOnly)
			}
		}
	}

	for _, closure := range g.CreatedClosures {
		for _, boundvar := range closure.boundVars {
			ppNodes("Bound var", w, boundvar, outEdgesOnly)
		}
		ppNodes("Closure", w, closure, outEdgesOnly)
	}

	for _, tup := range g.Returns {
		for _, r := range tup {
			ppNodes("Return", w, r, outEdgesOnly)
		}
	}

	for _, s := range g.SyntheticNodes {
		ppNodes("Synthetic", w, s, outEdgesOnly)
	}

	for _, group := range g.BoundLabelNodes {
		for _, s := range group {
			ppNodes("Bound by label", w, s, outEdgesOnly)
		}
	}

	for _, group := range g.AccessGlobalNodes {
		for _, s := range group {
			ppNodes("Global", w, s, outEdgesOnly)
		}
	}
}

func ppNodes(prefix string, w io.Writer, a GraphNode, outEdgesOnly bool) {
	if len(a.Out()) > 0 {
		fmt.Fprintf(w, "  %s %s:\n", prefix, a.String())
	}
	for n, edgeInfos := range a.Out() {
		for _, c := range edgeInfos {
			if c.Cond == nil || c.Cond.Satisfiable {
				ppEdge(w, n, c, "->")
			}
		}
	}
	if !outEdgesOnly {
		for n, c := range a.In() {
			if c.Cond == nil || c.Cond.Satisfiable {
				ppEdge(w, n, c, "<-")
			}
		}
	}
}

func ppEdge(w io.Writer, n GraphNode, c EdgeInfo, arrow string) {
	prefix := ""
	if c.Cond != nil && len(c.Cond.Conditions) > 0 {
		prefix += "?" + c.Cond.String()
	}
	if c.Index >= 0 {
		prefix += "#" + strconv.Itoa(c.Index)
	}
	prefixed := false
	for inPath, outPaths := range c.RelPath {
		for outPath := range outPaths {
			if inPath != "" || outPath != "" {
				if !prefixed {
					prefix += "@"
					prefixed = true
				}
				prefix += fmt.Sprintf("<%s,%s>", inPath, outPath)
			}
		}
	}
	if len(prefix) > 0 {
		prefix = "(" + prefix + ")"
	}
	fmt.Fprintf(w, "    %s %s %s\n", prefix, arrow, n.String())

}

// ForAllNodes applies f to all graph nodes
//
//gocyclo:ignore
func (g *SummaryGraph) ForAllNodes(f func(n GraphNode)) {
	if g == nil || g.Parent == nil {
		return
	}

	for _, a := range g.Params {
		f(a)
	}

	for _, a := range g.FreeVars {
		f(a)
	}

	for _, callNodes := range g.Callees {
		for _, callN := range callNodes {
			f(callN)
			for _, x := range callN.args {
				f(x)
			}
		}
	}

	for _, closure := range g.CreatedClosures {
		for _, boundvar := range closure.boundVars {
			f(boundvar)
		}
		f(closure)
	}

	for _, tup := range g.Returns {
		for _, r := range tup {
			f(r)
		}
	}

	for _, s := range g.SyntheticNodes {
		f(s)
	}

	for _, group := range g.BoundLabelNodes {
		for _, s := range group {
			f(s)
		}
	}

	for _, b := range g.BuiltinCalls {
		f(b)
	}

	for _, group := range g.AccessGlobalNodes {
		for _, s := range group {
			f(s)
		}
	}
}

// PrintNodes writes all the nodes in the graph to the writer
func (g *SummaryGraph) PrintNodes(w io.Writer) {
	g.ForAllNodes(func(n GraphNode) {
		fmt.Fprintf(w, "%s\n", n.String())
	})
}

// FullString returns a long string representation of the CallNode
func (a *CallNode) FullString() string {
	var elt []string

	if a == nil {
		return ""
	}

	if a.callSite != nil {
		s1 := fmt.Sprintf("callsite : \"%s\"", ftu.SanitizeRepr(a.callSite))
		elt = append(elt, s1)
	}
	if a.callee.Callee != nil {
		s2 := fmt.Sprintf("callee : \"%s\"", ftu.SanitizeRepr(a.callee.Callee))
		elt = append(elt, s2)
	}

	args := strings.Join(funcutil.Map(a.Args(), func(cg *CallNodeArg) string { return cg.String() }), ",")
	if len(args) > 0 {
		elt = append(elt, fmt.Sprintf("args : [%s]", args))
	}

	return "{" + strings.Join(elt, ", ") + "}"
}

// escape escapes the inner quotes in s so the graphviz output renders correctly.
func escapeString(s string) string {
	b := make([]rune, 0, len(s))
	for i, c := range s {
		if !(i == 0 || // ignore starting "
			(s[len(s)-1] == ';' && i == len(s)-2) || // ignore ending " when the string ends in ;
			(s[len(s)-1] == '"' && i == len(s)-1)) && // ignore ending " when string ends in "
			c == '"' {
			b = append(b, '\\')
		}
		b = append(b, c)
	}

	return ftu.Sanitize(string(b))
}
