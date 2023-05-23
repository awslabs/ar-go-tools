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
	"io"
	"strconv"
	"strings"

	"github.com/awslabs/argot/analysis/lang"
	"github.com/awslabs/argot/analysis/summaries"
	"github.com/awslabs/argot/internal/funcutil"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// ObjectPath contains information relative to the object pointed to.
type ObjectPath struct {
	// RelPath is the relative object memory path, e.g. * for dereference TODO: use this for field sensitivity
	RelPath string

	// Index is the relative tuple element reference by this path
	// if < 0, this means it is not used
	Index int

	// Cond is the condition under which this pointer/edge is valid.
	// An example usage is in the implementation of validators.
	Cond *ConditionInfo
}

// Graph Nodes

// GraphNode represents nodes in the function summary graph.
// Those nodes are either input argument nodes, callgraph nodes, call arguments nodes or return nodes.
type GraphNode interface {
	// ID returns the unique id of the node (id is unique within a given summary)
	ID() uint32

	// LongID returns the unique string id of the node, including the id of the parent function
	LongID() string

	// Graph returns the graph the node belongs to
	Graph() *SummaryGraph

	// Out returns the outgoing edges from the node. The ObjectPath specifies a possible "object path", e.g. a field
	// or a slice index, which refines the dataflow information (currently not in use, "" or "*" means everything in
	// the edge flows to the destination).
	Out() map[GraphNode]ObjectPath

	// In returns the incoming edges from the node. The ObjectPath specifies a possible "object path", e.g. a field
	// or a slice index, which refines the dataflow information (currently not in use, "" or "*" means everything in
	// the edge flows to the destination).
	In() map[GraphNode]ObjectPath

	// ParentName returns a string representing the parent object of the node.
	ParentName() string

	// Position returns the position of the node in the source code.
	Position(c *AnalyzerState) token.Position

	String() string

	Type() types.Type
}

type IndexedGraphNode interface {
	// ParentNode returns the parent graph node of and indexed graph node, e.g. the CallNode of a call argument
	// or the ClosureNode of a bound variable. Returns itself for a ParamNode
	ParentNode() GraphNode

	// Index returns the position of the node in the parent node structure (argument or bound variable position)
	Index() int
}

// ParamNode is a node that represents a parameter of the function (input argument)
type ParamNode struct {
	id      uint32
	parent  *SummaryGraph
	ssaNode *ssa.Parameter
	argPos  int
	out     map[GraphNode]ObjectPath
	in      map[GraphNode]ObjectPath
}

func (a *ParamNode) ID() uint32                    { return a.id }
func (a *ParamNode) Graph() *SummaryGraph          { return a.parent }
func (a *ParamNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *ParamNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *ParamNode) SsaNode() *ssa.Parameter       { return a.ssaNode }
func (a *ParamNode) Type() types.Type              { return a.ssaNode.Type() }
func (a *ParamNode) Position(c *AnalyzerState) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	} else {
		return lang.DummyPos
	}
}

// Index returns the parameter position of the node in the function's signature
func (a *ParamNode) Index() int { return a.argPos }

func (a *ParamNode) ParentNode() GraphNode { return a }

func (a *ParamNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	} else {
		return "ParamNode"
	}
}

func (a *ParamNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// FreeVarNode is a node that represents a free variable of the function (for closures)
type FreeVarNode struct {
	id      uint32
	parent  *SummaryGraph
	ssaNode *ssa.FreeVar
	fvPos   int
	out     map[GraphNode]ObjectPath
	in      map[GraphNode]ObjectPath
}

func (a *FreeVarNode) ID() uint32                    { return a.id }
func (a *FreeVarNode) Graph() *SummaryGraph          { return a.parent }
func (a *FreeVarNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *FreeVarNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *FreeVarNode) SsaNode() *ssa.FreeVar         { return a.ssaNode }
func (a *FreeVarNode) Type() types.Type              { return a.ssaNode.Type() }

func (a *FreeVarNode) Position(c *AnalyzerState) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	} else {
		return lang.DummyPos
	}
}

// Index returns the free variable position in the function's signature
func (a *FreeVarNode) Index() int { return a.fvPos }

func (a *FreeVarNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	} else {
		return "ParamNode"
	}
}

func (a *FreeVarNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// CallNodeArg is a node that represents the argument of a function call
type CallNodeArg struct {
	id       uint32
	parent   *CallNode
	ssaValue ssa.Value
	argPos   int
	out      map[GraphNode]ObjectPath
	in       map[GraphNode]ObjectPath
}

func (a *CallNodeArg) ID() uint32                    { return a.id }
func (a *CallNodeArg) Graph() *SummaryGraph          { return a.parent.parent }
func (a *CallNodeArg) Out() map[GraphNode]ObjectPath { return a.out }
func (a *CallNodeArg) In() map[GraphNode]ObjectPath  { return a.in }
func (a *CallNodeArg) Type() types.Type              { return a.ssaValue.Type() }

func (a *CallNodeArg) Position(c *AnalyzerState) token.Position {
	if a.ssaValue != nil {
		return c.Program.Fset.Position(a.ssaValue.Pos())
	} else {
		return lang.DummyPos
	}
}

// ParentNode returns the parent call node
func (a *CallNodeArg) ParentNode() *CallNode { return a.parent }

// Index returns the argument's position in the parent call node
func (a *CallNodeArg) Index() int { return a.argPos }

func (a *CallNodeArg) ParentName() string {
	if a.parent != nil && a.parent.parent != nil && a.parent.parent.Parent != nil {
		return a.parent.parent.Parent.Name()
	} else {
		return "CallNodeArg"
	}
}

func (a *CallNodeArg) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

func (a *CallNodeArg) Value() ssa.Value {
	return a.ssaValue
}

// CallNode is a node that represents a function call. It represents the value returned by the function call
// and also points at the CallNodeArg nodes that are its arguments
type CallNode struct {
	id            uint32
	parent        *SummaryGraph
	callSite      ssa.CallInstruction
	callee        CalleeInfo
	CalleeSummary *SummaryGraph
	args          []*CallNodeArg
	out           map[GraphNode]ObjectPath
	in            map[GraphNode]ObjectPath
}

func (a *CallNode) ID() uint32                    { return a.id }
func (a *CallNode) Graph() *SummaryGraph          { return a.parent }
func (a *CallNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *CallNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *CallNode) Type() types.Type {
	if call, ok := a.callSite.(*ssa.Call); ok {
		return call.Type()
	}
	return nil
}

func (a *CallNode) Position(c *AnalyzerState) token.Position {
	if a.callSite != nil && a.callSite.Common() != nil && a.callSite.Common().Value != nil {
		return c.Program.Fset.Position(a.callSite.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *CallNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

func (a *CallNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	} else {
		return "CallNode"
	}
}

func (a *CallNode) FindArg(v ssa.Value) *CallNodeArg {
	for _, argNode := range a.args {
		if argNode.ssaValue == v {
			return argNode
		}
	}
	return nil
}

// CallSite returns the call instruction corresponding to the call node
func (a *CallNode) CallSite() ssa.CallInstruction {
	return a.callSite
}

// Callee returns the function called at the call node
func (a *CallNode) Callee() *ssa.Function {
	return a.callee.Callee
}

func (a *CallNode) Args() []*CallNodeArg {
	return a.args
}

// FuncName returns the name of the function being called. It can be either the method name or a function name. The
// function could be a value (and not a static call), in which case the name of the value is returned.
func (a *CallNode) FuncName() string {
	if a.callSite != nil {
		if a.callSite.Common().IsInvoke() {
			return a.callSite.Common().Method.Name()
		} else {
			return a.callSite.Common().Value.Name()
		}
	} else {
		return "<CallNode with nil callSite>"
	}
}

// FuncString returns the string identified of the function being called. It can be either the method string or a
// function string. The function could be a value (and not a static call), in which case the name of the value
// is returned.
func (a *CallNode) FuncString() string {
	if a.callSite != nil {
		if a.callSite.Common().IsInvoke() {
			return a.callSite.Common().Method.String()
		} else {
			return a.callSite.Common().Value.String()
		}
	} else {
		return "<CallNode with nil callSite>"
	}
}

// A ReturnValNode is a node that represents a value returned by a function
type ReturnValNode struct {
	id     uint32
	index  int // when a function returns a tuple, a return node represents a single indexed value
	parent *SummaryGraph
	in     map[GraphNode]ObjectPath
}

func (a *ReturnValNode) Graph() *SummaryGraph          { return a.parent }
func (a *ReturnValNode) Out() map[GraphNode]ObjectPath { return nil }
func (a *ReturnValNode) ID() uint32                    { return a.id }
func (a *ReturnValNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *ReturnValNode) Index() int                    { return a.index }
func (a *ReturnValNode) Type() types.Type              { return a.parent.ReturnType() }
func (a *ReturnValNode) Position(c *AnalyzerState) token.Position {
	if a.parent != nil && a.parent.Parent != nil {
		return c.Program.Fset.Position(a.parent.Parent.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *ReturnValNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	} else {
		return "ReturnNode"
	}
}

func (a *ReturnValNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

type ClosureNode struct {
	id uint32

	// the parent of a closure node is the summary of the function in which the closure is created
	parent *SummaryGraph

	// the closureSummary is the data flow summary of the closure
	ClosureSummary *SummaryGraph

	// the instruction is the MakeClosure instruction
	instr *ssa.MakeClosure

	// the nodes corresponding to the bound variables
	boundVars []*BoundVarNode
	out       map[GraphNode]ObjectPath
	in        map[GraphNode]ObjectPath
}

func (a *ClosureNode) ID() uint32 { return a.id }

// Graph is the parent of a closure node is the summary of the function in which the closure is created.
func (a *ClosureNode) Graph() *SummaryGraph          { return a.parent }
func (a *ClosureNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *ClosureNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *ClosureNode) Type() types.Type              { return a.instr.Type() }

func (a *ClosureNode) Position(c *AnalyzerState) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *ClosureNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// Instr returns the makeClosure instruction corresponding to the closure node
func (a *ClosureNode) Instr() *ssa.MakeClosure {
	return a.instr
}

func (a *ClosureNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	} else {
		return "CallNode"
	}
}

func (a *ClosureNode) BoundVars() []*BoundVarNode {
	return a.boundVars
}

func (a *ClosureNode) FindBoundVar(v ssa.Value) *BoundVarNode {
	for _, bv := range a.boundVars {
		if bv.ssaValue == v {
			return bv
		}
	}
	return nil
}

// BoundVarNode is a node that represents the bound variable when a closure is created
type BoundVarNode struct {
	id uint32
	// the parent is the closure node that captures the variables
	parent *ClosureNode

	// the ssaValue is the value that corresponds to the bound variable in the SSA
	ssaValue ssa.Value

	// bPos is the position of the bound variable, and correspond to fvPos is the closure's summary
	bPos int

	out map[GraphNode]ObjectPath
	in  map[GraphNode]ObjectPath
}

func (a *BoundVarNode) ID() uint32                    { return a.id }
func (a *BoundVarNode) Graph() *SummaryGraph          { return a.parent.parent }
func (a *BoundVarNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *BoundVarNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *BoundVarNode) Type() types.Type              { return a.ssaValue.Type() }
func (a *BoundVarNode) Value() ssa.Value              { return a.ssaValue }

func (a *BoundVarNode) Position(c *AnalyzerState) token.Position {
	if a.ssaValue != nil {
		return c.Program.Fset.Position(a.ssaValue.Pos())
	} else {
		return lang.DummyPos
	}
}

// Index returns the position of the bound variable in the make closure instruction. It will correspond to the
// position of the matching variable in the closure's free variables.
func (a *BoundVarNode) Index() int { return a.bPos }

// ParentNode returns the closure node corresponding to the bound variable
func (a *BoundVarNode) ParentNode() *ClosureNode { return a.parent }

func (a *BoundVarNode) ParentName() string {
	if a.parent != nil && a.parent.parent != nil && a.parent.parent.Parent != nil {
		return a.parent.parent.Parent.Name()
	} else {
		return "BoundVarNode"
	}
}

func (a *BoundVarNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// A AccessGlobalNode represents a node where a global variable is accessed (read or written)
// In this context, a "write" is when data flows to the node, and a "read" is when data flows from the node
type AccessGlobalNode struct {
	id      uint32
	IsWrite bool            // IsWrite is true if the global is written at that location
	graph   *SummaryGraph   // the parent graph in which the read/write occurs
	instr   ssa.Instruction // the instruction where the global is read/written to
	Global  *GlobalNode     // the corresponding global node
	out     map[GraphNode]ObjectPath
	in      map[GraphNode]ObjectPath
}

func (a *AccessGlobalNode) ID() uint32                    { return a.id }
func (a *AccessGlobalNode) Graph() *SummaryGraph          { return a.graph }
func (a *AccessGlobalNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *AccessGlobalNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *AccessGlobalNode) Type() types.Type              { return a.Global.Type() }

func (a *AccessGlobalNode) Position(c *AnalyzerState) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *AccessGlobalNode) Instr() ssa.Instruction { return a.instr }

func (a *AccessGlobalNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

func (a *AccessGlobalNode) LongID() string {
	return "#" + strconv.Itoa(int(a.graph.ID)) + "." + strconv.Itoa(int(a.id))
}

// A SyntheticNode can be used to represent any other type of node.
type SyntheticNode struct {
	id     uint32
	parent *SummaryGraph            // the parent of a SyntheticNode is the summary of the function in which it appears
	instr  ssa.Instruction          // a SyntheticNode must correspond to a specific instruction
	label  string                   // the label can be used to record information about synthetic nodes
	out    map[GraphNode]ObjectPath // the out maps the node to other nodes to which data flows
	in     map[GraphNode]ObjectPath // the in maps the node to other nodes from which data flows
}

func (a *SyntheticNode) ID() uint32                    { return a.id }
func (a *SyntheticNode) Graph() *SummaryGraph          { return a.parent }
func (a *SyntheticNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *SyntheticNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *SyntheticNode) Type() types.Type {
	if val, ok := a.instr.(ssa.Value); ok {
		return val.Type()
	}
	return nil
}

func (a *SyntheticNode) Position(c *AnalyzerState) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return lang.DummyPos
	}
}

// Instr correspond to the instruction matching that synthetic node
func (a *SyntheticNode) Instr() ssa.Instruction { return a.instr }

func (a *SyntheticNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

func (a *SyntheticNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// A BoundLabelNode is used to track dataflow from modified bound variables to closure bodies
type BoundLabelNode struct {
	id         uint32
	parent     *SummaryGraph   // the parent of a SyntheticNode is the summary of the function in which it appears
	instr      ssa.Instruction // a SyntheticNode must correspond to a specific instruction
	targetInfo BindingInfo     // the targetInfo may be point to another function
	targetAnon *SummaryGraph   // the targetAnon should be the anonymous function designated by the targetInfo
	label      *pointer.Label
	out        map[GraphNode]ObjectPath // the out maps the node to other nodes to which data flows
	in         map[GraphNode]ObjectPath // the in maps the node to other nodes from which data flows
}

func (a *BoundLabelNode) ID() uint32                    { return a.id }
func (a *BoundLabelNode) Graph() *SummaryGraph          { return a.parent }
func (a *BoundLabelNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *BoundLabelNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *BoundLabelNode) Type() types.Type              { return a.targetInfo.Type() }

func (a *BoundLabelNode) Position(c *AnalyzerState) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return lang.DummyPos
	}
}

// Instr correspond to the instruction matching that synthetic node
func (a *BoundLabelNode) Instr() ssa.Instruction { return a.instr }

func (a *BoundLabelNode) DestInfo() BindingInfo { return a.targetInfo }

func (a *BoundLabelNode) Index() int { return a.targetInfo.BoundIndex }

func (a *BoundLabelNode) DestClosure() *SummaryGraph { return a.targetAnon }

func (a *BoundLabelNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

func (a *BoundLabelNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// Graph

// SummaryGraph is the function dataflow summary graph.
type SummaryGraph struct {
	// the unique ID of the summary
	ID uint32

	// true if summary graph is Constructed, false if it is a dummy
	Constructed bool

	// true if the summary is built from an interface's dataflow contract
	IsInterfaceContract bool

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

	// the MakeClosure nodes in the function  are linked to ClosureNode
	CreatedClosures map[ssa.Instruction]*ClosureNode

	// the MakeClosure nodes referring to this function
	ReferringMakeClosures map[ssa.Instruction]*ClosureNode

	// the synthetic nodes of the function
	SyntheticNodes map[ssa.Instruction]*SyntheticNode

	// the label nodes of the function
	BoundLabelNodes map[ssa.Instruction]*BoundLabelNode

	// the nodes accessing global information
	AccessGlobalNodes map[ssa.Instruction]map[ssa.Value]*AccessGlobalNode

	// the return instructions are linked to ReturnNode, one per value in a tuple returned
	Returns map[ssa.Instruction][]*ReturnValNode

	// errors can be used to accumulate errors that were encountered while building the summary graph
	errors map[error]bool

	// nodeCounter is used to track the number of nodes in the graph
	nodeCounter uint32
}

// NewSummaryGraph builds a new summary graph given a function and its corresponding node.
// Returns a non-nil value if and only if f is non-nil.
// If non-nil, the returned summary graph is marked as not constructed.
func NewSummaryGraph(f *ssa.Function, id uint32) *SummaryGraph {
	if f == nil {
		return nil
	}
	g := &SummaryGraph{
		ID:                    id,
		Constructed:           false,
		IsInterfaceContract:   false,
		Parent:                f,
		Params:                make(map[ssa.Node]*ParamNode, len(f.Params)),
		FreeVars:              make(map[ssa.Node]*FreeVarNode, len(f.FreeVars)),
		Callees:               make(map[ssa.CallInstruction]map[*ssa.Function]*CallNode),
		Callsites:             make(map[ssa.CallInstruction]*CallNode),
		Returns:               make(map[ssa.Instruction][]*ReturnValNode),
		CreatedClosures:       make(map[ssa.Instruction]*ClosureNode),
		ReferringMakeClosures: make(map[ssa.Instruction]*ClosureNode),
		AccessGlobalNodes:     make(map[ssa.Instruction]map[ssa.Value]*AccessGlobalNode),
		SyntheticNodes:        make(map[ssa.Instruction]*SyntheticNode),
		BoundLabelNodes:       make(map[ssa.Instruction]*BoundLabelNode),
		errors:                map[error]bool{},
		nodeCounter:           0,
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
		returnNodes[i] = &ReturnValNode{parent: g, id: uint32(g.nodeCounter), index: i}
		g.nodeCounter++
	}

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

	return g
}

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
				node.Global.AddWriteLoc(node)
			} else if len(node.out) > 0 {
				node.Global.AddReadLoc(node)
			}
		}
	}
}

// addError adds an error to the summary graph. Can be modified to change the behavior when an error is encountered
// when building the summary
func (g *SummaryGraph) addError(e error) {
	g.errors[e] = true
}

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
		id:      g.nodeCounter,
		parent:  g,
		ssaNode: param,
		out:     make(map[GraphNode]ObjectPath),
		in:      make(map[GraphNode]ObjectPath),
		argPos:  pos,
	}
	g.nodeCounter += 1
}

// addFreeVar adds a free variable to the summary
// @requires g != nil
func (g *SummaryGraph) addFreeVar(fv *ssa.FreeVar, pos int) {
	if fv == nil {
		return
	}

	g.FreeVars[fv] = &FreeVarNode{
		id:      g.nodeCounter,
		parent:  g,
		ssaNode: fv,
		out:     make(map[GraphNode]ObjectPath),
		in:      make(map[GraphNode]ObjectPath),
		fvPos:   pos,
	}
	g.nodeCounter += 1
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

// AddCallInstr adds a call site to the summary from a call instruction (use when no call graph is available)
// @requires g != nil
func (g *SummaryGraph) AddCallInstr(c *AnalyzerState, instr ssa.CallInstruction) {
	// Already seen this instruction? Multiple calls of this function will not gather more information.
	if _, ok := g.Callees[instr]; ok {
		return
	}

	args := lang.GetArgs(instr)
	callees, err := c.ResolveCallee(instr, true)
	if err != nil {
		c.Logger.Fatalf("missing information in state (%s), could not resolve callee in instruction %s", err,
			instr.String())
	}
	// Add each callee as a node for this call instruction
	for _, callee := range callees {
		node := &CallNode{
			id:       g.nodeCounter,
			parent:   g,
			callee:   callee,
			args:     make([]*CallNodeArg, len(args)),
			callSite: instr,
			out:      make(map[GraphNode]ObjectPath),
			in:       make(map[GraphNode]ObjectPath),
		}
		g.nodeCounter += 1

		for pos, arg := range args {
			argNode := &CallNodeArg{
				id:       g.nodeCounter,
				parent:   node,
				ssaValue: arg,
				argPos:   pos,
				out:      make(map[GraphNode]ObjectPath),
				in:       make(map[GraphNode]ObjectPath),
			}
			g.nodeCounter += 1
			node.args[pos] = argNode
		}
		g.addCallNode(node)
	}

	if len(callees) == 0 {

		// TODO: remove that when we have a method to resolve all callees
		node := &CallNode{
			id:       g.nodeCounter,
			parent:   g,
			callee:   CalleeInfo{},
			args:     make([]*CallNodeArg, len(args)),
			callSite: instr,
			out:      make(map[GraphNode]ObjectPath),
			in:       make(map[GraphNode]ObjectPath),
		}
		g.nodeCounter += 1

		for pos, arg := range args {
			argNode := &CallNodeArg{
				id:       g.nodeCounter,
				parent:   node,
				ssaValue: arg,
				out:      make(map[GraphNode]ObjectPath),
				in:       make(map[GraphNode]ObjectPath),
			}
			g.nodeCounter += 1
			node.args[pos] = argNode
		}
		g.addCallNode(node)
	}
}

// addReturn adds a return node to the summary
// @requires g != nil
func (g *SummaryGraph) addReturn(instr ssa.Instruction, node *ReturnValNode) {
	n := g.Parent.Signature.Results().Len()
	// No value is returned
	if n <= 0 {
		return
	}
	if _, ok := g.Returns[instr]; !ok {
		g.Returns[instr] = make([]*ReturnValNode, n)
	}
	g.Returns[instr][node.index] = node
}

// AddClosure adds a closure node to the summary
// @requires g != nil
func (g *SummaryGraph) AddClosure(x *ssa.MakeClosure) {
	if _, ok := g.CreatedClosures[x]; ok {
		return
	}

	node := &ClosureNode{
		id:             g.nodeCounter,
		parent:         g,
		ClosureSummary: nil,
		instr:          x,
		boundVars:      []*BoundVarNode{},
		out:            make(map[GraphNode]ObjectPath),
		in:             make(map[GraphNode]ObjectPath),
	}
	g.nodeCounter += 1

	g.CreatedClosures[x] = node

	for pos, binding := range x.Bindings {
		bindingNode := &BoundVarNode{
			id:       g.nodeCounter,
			parent:   node,
			ssaValue: binding,
			bPos:     pos,
			out:      make(map[GraphNode]ObjectPath),
			in:       make(map[GraphNode]ObjectPath),
		}
		g.nodeCounter += 1
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
			id:      g.nodeCounter,
			IsWrite: false,
			graph:   g,
			instr:   instr,
			Global:  global,
			out:     make(map[GraphNode]ObjectPath),
			in:      make(map[GraphNode]ObjectPath),
		}
		g.nodeCounter += 1
		g.AccessGlobalNodes[instr][global.value] = node
	}
}

// AddSyntheticNode adds a synthetic node to the summary. instr will be the instruction of the synthetic node, and
// label will be its label. The node is created only if the instruction is not present in the g.syntheticNodes map.
// If a node is created, then g.syntheticNodes[instr] will be the node created.
// @requires g != nil
func (g *SummaryGraph) AddSyntheticNode(instr ssa.Instruction, label string) {
	if _, ok := g.SyntheticNodes[instr]; !ok {
		node := &SyntheticNode{
			id:     g.nodeCounter,
			parent: g,
			instr:  instr,
			label:  label,
			out:    make(map[GraphNode]ObjectPath),
			in:     make(map[GraphNode]ObjectPath),
		}
		g.nodeCounter += 1
		g.SyntheticNodes[instr] = node
	}
}

func (g *SummaryGraph) AddBoundLabelNode(instr ssa.Instruction, label *pointer.Label, target BindingInfo) {
	if _, ok := g.BoundLabelNodes[instr]; !ok {
		node := &BoundLabelNode{
			id:         g.nodeCounter,
			parent:     g,
			instr:      instr,
			label:      label,
			targetInfo: target,
			out:        make(map[GraphNode]ObjectPath),
			in:         make(map[GraphNode]ObjectPath),
		}
		g.nodeCounter += 1
		g.BoundLabelNodes[instr] = node
	}
}

func (g *SummaryGraph) AddSyntheticNodeEdge(mark Mark, instr ssa.Instruction, label string, info *ConditionInfo) {
	node, ok := g.SyntheticNodes[instr]
	if !ok {
		return
	}
	g.addEdge(mark, node, info)
}

func (g *SummaryGraph) AddBoundLabelNodeEdge(mark Mark, instr ssa.Instruction, info *ConditionInfo) {
	node, ok := g.BoundLabelNodes[instr]
	if !ok {
		return
	}
	g.addEdge(mark, node, info)
}

// Functions to add edges to the graph

// addEdge adds an edge between source and targetInfo in the summary graph g.
// @requires g != nil
func (g *SummaryGraph) addEdge(source Mark, dest GraphNode, info *ConditionInfo) {
	// This function's goal is to define how the source of an edge is obtained in the summary given a Mark that
	// is produced in the intra-procedural analysis.

	if source.IsParameter() {
		if sourceArgNode, ok := g.Params[source.Node]; ok && sourceArgNode != dest {
			sourceArgNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
			addInEdge(dest, sourceArgNode, ObjectPath{source.RegionPath, source.Index, info})
		}
	}

	if source.IsCallSiteArg() {
		// A CallSite source node must be a CallInstruction
		sourceCallInstr := source.Node.(ssa.CallInstruction)
		// and it must have a qualifier representing the argument
		if sourceNodes, ok := g.Callees[sourceCallInstr]; ok {
			for _, sourceNode := range sourceNodes {
				sourceCallArgNode := sourceNode.FindArg(source.Qualifier)
				if sourceCallArgNode != nil && sourceCallArgNode != dest {
					sourceCallArgNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
					addInEdge(dest, sourceCallArgNode, ObjectPath{source.RegionPath, source.Index, info})
				}
			}
		}
	}

	if source.IsCallReturn() {
		// A CallReturn source node must be a CallInstruction
		sourceCallInstr := source.Node.(ssa.CallInstruction)
		if sourceNodes, ok := g.Callees[sourceCallInstr]; ok {
			for _, sourceNode := range sourceNodes {
				if sourceNode != dest {
					sourceNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
					addInEdge(dest, sourceNode, ObjectPath{source.RegionPath, source.Index, info})
				}
			}

		}
	}

	if source.IsFreeVar() {
		if sourceFreeVarNode, ok := g.FreeVars[source.Node]; ok && sourceFreeVarNode != dest {
			sourceFreeVarNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
			addInEdge(dest, sourceFreeVarNode, ObjectPath{source.RegionPath, source.Index, info})
		}
	}

	if source.IsBoundVar() {
		// A bound var source's node must be a make closure node
		sourceClosure := source.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[sourceClosure]; ok {
			bvNode := cNode.FindBoundVar(source.Qualifier)
			if bvNode != nil && bvNode != dest {
				bvNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
				addInEdge(dest, bvNode, ObjectPath{source.RegionPath, source.Index, info})
			}
		}
	}

	if source.IsClosure() {
		sourceClosure := source.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[sourceClosure]; ok {
			if cNode != dest {
				cNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
				addInEdge(dest, cNode, ObjectPath{source.RegionPath, source.Index, info})
			}
		}
	}

	if source.IsSynthetic() {
		// A synthetic source can refer to any instruction
		sourceInstr := source.Node.(ssa.Instruction)
		if sourceNode, ok := g.SyntheticNodes[sourceInstr]; ok {
			if sourceNode != dest {
				sourceNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
				addInEdge(dest, sourceNode, ObjectPath{source.RegionPath, source.Index, info})
			}
		}
	}

	if source.IsGlobal() {
		sourceInstr := source.Node.(ssa.Instruction)
		if group, ok := g.AccessGlobalNodes[sourceInstr]; ok {
			if sourceNode, ok := group[source.Qualifier]; ok {
				sourceNode.out[dest] = ObjectPath{source.RegionPath, source.Index, info}
				addInEdge(dest, sourceNode, ObjectPath{source.RegionPath, source.Index, info})
			}
		}
	}
}

// AddCallArgEdge adds an edge in the summary from a mark to a function call argument.
// @requires g != nil
func (g *SummaryGraph) AddCallArgEdge(mark Mark, call ssa.CallInstruction, arg ssa.Value, cond *ConditionInfo) {
	callNodes := g.Callees[call]
	if callNodes == nil {
		return
	}

	for _, callNode := range callNodes {
		callNodeArg := callNode.FindArg(arg)
		if callNodeArg == nil {
			g.addError(fmt.Errorf("attempting to set call arg edge but no call arg node"))
			return
		}
		g.addEdge(mark, callNodeArg, cond)
	}
}

// AddCallNodeEdge adds an edge that flows to a call node.
func (g *SummaryGraph) AddCallNodeEdge(mark Mark, call ssa.CallInstruction, cond *ConditionInfo) {
	callNodes := g.Callees[call]
	if callNodes == nil {
		return
	}
	for _, callNode := range callNodes {
		g.addEdge(mark, callNode, cond)
	}
}

// AddBoundVarEdge adds an edge in the summary from a mark to a function call argument.
// @requires g != nil
func (g *SummaryGraph) AddBoundVarEdge(mark Mark, closure *ssa.MakeClosure, v ssa.Value, cond *ConditionInfo) {
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

// AddReturnEdge adds an edge in the summary from the mark to a return instruction
// @requires g != nil
func (g *SummaryGraph) AddReturnEdge(mark Mark, retInstr ssa.Instruction, tupleIndex int, cond *ConditionInfo) {
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

// AddParamEdge adds an edge in the summary from the mark to a parameter of the function
func (g *SummaryGraph) AddParamEdge(mark Mark, param ssa.Node, cond *ConditionInfo) {
	paramNode := g.Params[param]

	if paramNode == nil {
		g.addError(fmt.Errorf("attempting to set param edge but no param node"))
	}

	g.addEdge(mark, paramNode, cond)
}

// AddGlobalEdge adds an edge from a mark to a GlobalNode
func (g *SummaryGraph) AddGlobalEdge(mark Mark, loc ssa.Instruction, v *ssa.Global, cond *ConditionInfo) {
	node := g.AccessGlobalNodes[loc][v]

	if node == nil {
		// TODO: debug this
		//g.addError(fmt.Errorf("attempting to set global edge but no global node"))
		return
	} else {
		// Set node to written
		node.IsWrite = true
	}

	g.addEdge(mark, node, cond)
}

func addInEdge(dest GraphNode, source GraphNode, path ObjectPath) {
	switch node := dest.(type) {
	case *ParamNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *CallNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *CallNodeArg:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *FreeVarNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *ReturnValNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *ClosureNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *SyntheticNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *AccessGlobalNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *BoundVarNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
		node.in[source] = path
	case *BoundLabelNode:
		if node.in == nil {
			node.in = make(map[GraphNode]ObjectPath)
		}
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
			srcArg.out[destArg] = ObjectPath{"", 0, nil}

			if destArg.in == nil {
				destArg.in = make(map[GraphNode]ObjectPath)
			}
			destArg.in[srcArg] = ObjectPath{"", 0, nil}
			return true
		}
	}
	return false
}

// AddFreeVarEdge adds an edge in the summary from the mark to a bound variable of a closure
func (g *SummaryGraph) AddFreeVarEdge(mark Mark, freeVar ssa.Node, cond *ConditionInfo) {
	freeVarNode := g.FreeVars[freeVar]
	if freeVarNode == nil {
		g.addError(fmt.Errorf("attempting to set free var edge but no free var node"))
	}
	g.addEdge(mark, freeVarNode, cond)
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
			srcArg.out[retNode[pos]] = ObjectPath{"", pos, nil}
			if retNode[pos].in == nil {
				retNode[pos].in = make(map[GraphNode]ObjectPath)
			}
			retNode[pos].in[srcArg] = ObjectPath{"", pos, nil}
			return true
		}
	}
	return false
}

// LoadPredefinedSummary searches for a summary for f in the summaries packages and builds the SummaryGraph it
// represents. The resulting summary will only contain parameter and return nodes and edges between those. It will
// not include any call node or call argument nodes.
//
// If f is nil, or f has no predefined summary, then the function returns nil.
// If f has a predefined summary, then the returned summary graph is marked as constructed.
// cg can be nil.
func LoadPredefinedSummary(f *ssa.Function, id uint32) *SummaryGraph {
	preDef, ok := summaries.SummaryOfFunc(f)
	if !ok {
		return nil
	}
	summaryBase := NewSummaryGraph(f, id)
	summaryBase.PopulateGraphFromSummary(preDef, false)
	return summaryBase
}

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
}

// Utilities for printing graphs

func (a *ParamNode) String() string {
	if a == nil {
		return ""
	} else {
		fname := ""
		if a.parent.Parent != nil {
			fname = a.parent.Parent.Name()
		}
		return fmt.Sprintf("\"[#%d.%d] %s of %s [%d]\"",
			a.parent.ID, a.ID(), a.SsaNode().String(), fname, a.Index())
	}
}

func (a *CallNodeArg) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] @arg %d:%s in %s \"",
		a.ParentNode().parent.ID, a.ID(), a.Index(), a.ssaValue.Name(),
		strings.Trim(a.ParentNode().String(), "\""))
}

func (a *CallNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] (%s)call: %s in %s\"",
		a.parent.ID, a.id, a.callee.Type.Code(), a.callSite.String(), a.callSite.Parent().Name())
}

func (a *ReturnValNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] %s.return.%d\"", a.parent.ID, a.id, a.parent.Parent.Name(), a.index)
}

func (a *SyntheticNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] synthetic: %s = %s\"",
		a.parent.ID, a.id, a.instr.(ssa.Value).Name(), a.instr.String())
}

func (a *FreeVarNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] freevar:%s\"", a.parent.ID, a.id, a.ssaNode.Name())
}

func (a *BoundVarNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] boundvar:%s\"", a.ParentNode().parent.ID, a.id, a.ssaValue.String())
}

func (a *ClosureNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] closure:%s\"", a.parent.ID, a.id, a.instr.String())
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
		a.graph.ID, a.id, a.Global.value.String(), a.instr.String(), typ)
}

func (a *BoundLabelNode) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("\"[#%d.%d] bound: %s to %s #%d\"", a.parent.ID, a.id, a.instr.String(),
		a.targetInfo.MakeClosure.String(), a.targetInfo.BoundIndex)
}

// Print the summary graph to w in the graphviz format.
// If g is nil, then prints the empty graph "subgraph {}"
func (g *SummaryGraph) Print(outEdgesOnly bool, w io.Writer) {
	if g == nil || g.Parent == nil {
		fmt.Fprintf(w, "subgraph {}\n")
		return
	}
	fmt.Fprintf(w, "subgraph \"cluster_%s\" {\n", g.Parent.Name())
	fmt.Fprintf(w, "\tlabel=\"%s\";\n", g.Parent.Name()) // label each subgraph with the function name
	for _, a := range g.Params {
		for n := range a.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escape(a.String()), escape(n.String()))
		}
		if !outEdgesOnly {
			for n := range a.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(a.String()), escape(n.String()))
			}
		}
	}

	for _, a := range g.FreeVars {
		for n := range a.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escape(a.String()), escape(n.String()))
		}
		if !outEdgesOnly {
			for n := range a.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(a.String()), escape(n.String()))
			}
		}
	}

	for _, callNodes := range g.Callees {
		for _, callN := range callNodes {
			for n, obj := range callN.Out() {
				fmt.Fprintf(w, "\t%s.%d -> %s;\n", escape(callN.String()), obj.Index, escape(n.String()))
			}
			if !outEdgesOnly {
				for n := range callN.In() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escape(callN.String()), escape(n.String()))
				}
			}
			for _, x := range callN.args {
				for n := range x.Out() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escape(x.String()), escape(n.String()))
				}
				if !outEdgesOnly {
					for n := range x.In() {
						fmt.Fprintf(w, "\t%s -> %s;\n", escape(x.String()), escape(n.String()))
					}
				}
			}
		}
	}

	for _, closure := range g.CreatedClosures {
		for _, boundvar := range closure.boundVars {
			for n := range boundvar.Out() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(boundvar.String()), escape(n.String()))
			}
			if !outEdgesOnly {
				for n := range boundvar.In() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escape(boundvar.String()), escape(n.String()))
				}
			}
		}
		for o := range closure.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escape(closure.String()), escape(o.String()))
		}
		if !outEdgesOnly {
			for i := range closure.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(closure.String()), escape(i.String()))
			}
		}
	}

	for _, retTuple := range g.Returns {
		for _, r := range retTuple {
			// a return node can be nil if its value is constant
			if r == nil {
				continue
			}
			for n, obj := range r.Out() {
				fmt.Fprintf(w, "\t%s.%d -> %s;\n", escape(r.String()), obj.Index, escape(n.String()))
			}
			if !outEdgesOnly {
				for n, obj := range r.In() {
					fmt.Fprintf(w, "\t%s.%d -> %s;\n", escape(r.String()), obj.Index, escape(n.String()))
				}
			}
		}
	}

	for _, s := range g.SyntheticNodes {
		for n := range s.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escape(s.String()), escape(n.String()))
		}
		if !outEdgesOnly {
			for n := range s.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(s.String()), escape(n.String()))
			}
		}
	}

	for _, s := range g.BoundLabelNodes {
		for n := range s.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escape(s.String()), escape(n.String()))
		}
		if !outEdgesOnly {
			for n := range s.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(s.String()), escape(n.String()))
			}
		}
	}

	for _, group := range g.AccessGlobalNodes {
		for _, s := range group {
			for n := range s.Out() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(s.String()), escape(n.String()))
			}
			if !outEdgesOnly {
				for n := range s.In() {
					fmt.Fprintf(w, "\t%s -> %s;\n", escape(s.String()), escape(n.String()))
				}
			}
		}
	}

	fmt.Fprint(w, "}\n")
}

// PrettyPrint prints the summary graph to w in a readable format.
func (g *SummaryGraph) PrettyPrint(outEdgesOnly bool, w io.Writer) {
	if g == nil || g.Parent == nil {
		fmt.Fprintf(w, "Empty graph!\n")
		return
	}
	fmt.Fprintf(w, "Summary of %s:\n", g.Parent.Name())
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

	for _, s := range g.BoundLabelNodes {
		ppNodes("Bound by label", w, s, outEdgesOnly)
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
	for n, c := range a.Out() {
		if c.Cond == nil || c.Cond.Satisfiable {
			ppEdge(w, n, c, "->")
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

func ppEdge(w io.Writer, n GraphNode, c ObjectPath, arrow string) {
	prefix := ""
	if c.Cond != nil && len(c.Cond.Conditions) > 0 {
		prefix += "?" + c.Cond.String()
	}
	if c.Index >= 0 {
		prefix += "#" + strconv.Itoa(c.Index)
	}
	if len(prefix) > 0 {
		prefix = "(" + prefix + ")"
	}
	fmt.Fprintf(w, "    %s %s %s\n", prefix, arrow, n.String())

}

// ForAllNodes applies f to all graph nodes
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

	for _, s := range g.BoundLabelNodes {
		f(s)
	}

	for _, group := range g.AccessGlobalNodes {
		for _, s := range group {
			f(s)
		}
	}
}

func (g *SummaryGraph) PrintNodes(w io.Writer) {
	g.ForAllNodes(func(n GraphNode) {
		fmt.Fprintf(w, "%s\n", n.String())
	})
}

func (a *CallNode) FullString() string {
	var elt []string

	if a == nil {
		return ""
	}

	if a.callSite != nil {
		s1 := fmt.Sprintf("callsite : \"%s\"", a.callSite.String())
		elt = append(elt, s1)
	}
	if a.callee.Callee != nil {
		s2 := fmt.Sprintf("callee : \"%s\"", a.callee.Callee.String())
		elt = append(elt, s2)
	}

	args := strings.Join(funcutil.Map(a.Args(), func(cg *CallNodeArg) string { return cg.String() }), ",")
	if len(args) > 0 {
		elt = append(elt, fmt.Sprintf("args : [%s]", args))
	}

	return "{" + strings.Join(elt, ", ") + "}"
}

// escape escapes the inner quotes in s so the graphviz output renders correctly.
func escape(s string) string {
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

	return string(b)
}
