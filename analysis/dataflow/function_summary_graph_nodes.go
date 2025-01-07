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
	"strconv"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
	"golang.org/x/tools/go/ssa"
)

// LocSet is a set of locations; here, a set of instructions
type LocSet = map[ssa.Instruction]bool

// EdgeInfo contains information relative to the object pointed to.
type EdgeInfo struct {
	// RelPath is the relative output object access path, e.g. ".A" for field A
	RelPath map[string]map[string]bool

	// Index is the relative tuple element reference by this Path
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

	// Out returns the outgoing edges from the node. The DataflowEdge specifies a possible "object Path", e.g. a field
	// or a slice index, which refines the dataflow information
	Out() map[GraphNode][]EdgeInfo

	// In returns the incoming edges from the node. The DataflowEdge specifies a possible "object Path", e.g. a field
	// or a slice index, which refines the dataflow information (currently not in use, "" or "*" means everything in
	// the edge flows to the destination).
	In() map[GraphNode]EdgeInfo

	// ParentName returns a string representing the parent object of the node.
	ParentName() string

	// Position returns the position of the node in the source code.
	Position(c *State) token.Position

	// String prints the string representation of the node.
	// All strings methods should return sanitized output. That is, the underlying information related to the source
	// code is sanitized before being returned.
	String() string

	// Type returns the type of the node
	Type() types.Type

	// Marks returns the loc-set of the node
	Marks() LocSet

	// SetLocs sets the loc-set of the node
	SetLocs(LocSet)

	// Equal lifts equality to the interface level
	Equal(GraphNode) bool
}

// An IndexedGraphNode is a graph node with additional information abouts its index in a parent node (e.g. argument
// in a call)
type IndexedGraphNode interface {
	// ParentNode returns the parent graph node of and indexed graph node, e.g. the CallNode of a call argument
	// or the ClosureNode of a bound variable. Returns itself for a ParamNode
	ParentNode() GraphNode

	// Index returns the position of the node in the parent node structure (argument or bound variable position)
	Index() int
}

// Instr returns the SSA instruction corresponding to node. Returns nil if there is no SSA instruction.
func Instr(node GraphNode) ssa.Instruction {
	// The instruction depends on the type of the node: a call node or synthetic node are directly
	// related to an instruction, whereas the instruction of a call node argument is the instruction of its
	// parent call node.
	switch node := node.(type) {
	case *CallNode:
		return node.CallSite()
	case *CallNodeArg:
		return node.ParentNode().CallSite()
	case *SyntheticNode:
		return node.Instr()
	case *IfNode:
		return node.SsaNode()
	}

	return nil
}

// NodeSummary returns a string summary of the node, without using any escape codes.
func NodeSummary(g GraphNode) string {
	switch x := g.(type) {
	case *ParamNode:
		return fmt.Sprintf("Parameter %s (type %s) of %s",
			x.ssaNode.Name(),
			x.Type().String(),
			fmt.Sprintf("%q", x.parent.Parent.Name()))
	case *BuiltinCallNode:
		return fmt.Sprintf("Call to builtin %s", x.name)
	case *CallNode:
		return fmt.Sprintf("Result of call to %s (type %s)",
			x.Callee().Name(),
			x.Type().String())
	case *CallNodeArg:
		return fmt.Sprintf("Argument #%d (type %s) in call to %s",
			x.Index(),
			x.Type().String(),
			x.ParentNode().Callee().Name())
	case *ReturnValNode:
		return fmt.Sprintf("Return value %d (type %s) of %s",
			x.Index(),
			x.Type().String(),
			x.ParentName())
	case *ClosureNode:
		return fmt.Sprintf("Closure")
	case *BoundLabelNode:
		return fmt.Sprintf("Bound label of type %s", x.targetInfo.Type().String())
	case *SyntheticNode:
		return fmt.Sprintf("Synthetic node")
	case *BoundVarNode:
		return "Bound variable"
	case *FreeVarNode:
		return fmt.Sprintf("Free variable #%d of %q", x.fvPos, x.ssaNode.Parent().String())
	case *AccessGlobalNode:
		return fmt.Sprintf("Global variable %q", x.Global.String())
	}
	return ""
}

// TermNodeSummary returns a string summary of the node, highlighting with terminal colors
// green indicates a relative index/argument name,
// magenta is used for function names,
// italic is used for types.
func TermNodeSummary(g GraphNode) string {
	switch x := g.(type) {
	case *ParamNode:
		return fmt.Sprintf("Parameter %s (type %s) of %s",
			formatutil.Green(x.ssaNode.Name()),
			formatutil.Italic(x.Type().String()),
			formatutil.Magenta(fmt.Sprintf("%q", x.parent.Parent.Name())))
	case *CallNode:
		return fmt.Sprintf("Result of call to %s (type %s)",
			formatutil.Magenta(x.Callee().Name()),
			formatutil.Italic(x.Type().String()))
	case *CallNodeArg:
		return fmt.Sprintf("Argument #%s (type %s) in call to %s",
			formatutil.Green(x.Index()),
			formatutil.Italic(x.Type().String()),
			formatutil.Magenta(x.ParentNode().Callee().Name()))
	case *ReturnValNode:
		return fmt.Sprintf("Return value %s (type %s) of %s",
			formatutil.Green(x.Index()),
			formatutil.Italic(x.Type().String()),
			formatutil.Magenta(x.ParentName()))
	case *ClosureNode:
		return fmt.Sprintf("Closure")
	case *BoundLabelNode:
		return fmt.Sprintf("Bound label of type %s", formatutil.Italic(x.targetInfo.Type().String()))
	case *SyntheticNode:
		return fmt.Sprintf("Synthetic node")
	case *BoundVarNode:
		return "Bound variable"
	case *FreeVarNode:
		return fmt.Sprintf("Free variable #%s of %q", formatutil.Green(x.fvPos), x.ssaNode.Parent().String())
	case *AccessGlobalNode:
		return fmt.Sprintf("Global variable %q", formatutil.Red(x.Global.String()))
	}
	return ""
}

// shortNodeSummary returns a condensed summary (no whitespace) of a node.
func shortNodeSummary(g GraphNode) string {
	switch x := g.(type) {
	case *ParamNode:
		return fmt.Sprintf("param:%s:%s", x.ssaNode.Name(), x.parent.Parent.Name())
	case *CallNode:
		return fmt.Sprintf("call:%s", x.Callee().String())
	case *CallNodeArg:
		return fmt.Sprintf("arg#%v:%s", x.Index(), x.ParentNode().Callee().Name())
	case *ReturnValNode:
		return fmt.Sprintf("ret#%d:%s", x.Index(), x.ParentName())
	case *ClosureNode:
		return "closure"
	case *BoundLabelNode:
		return "bound-label"
	case *SyntheticNode:
		return "synth"
	case *BoundVarNode:
		return "bound-var"
	case *FreeVarNode:
		return "free-var"
	case *AccessGlobalNode:
		return fmt.Sprintf("global:%v", x.Global.Value())
	}
	return ""
}

// ParamNode is a node that represents a parameter of the function (input argument)
type ParamNode struct {
	id      uint32
	parent  *SummaryGraph
	ssaNode *ssa.Parameter
	argPos  int
	out     map[GraphNode][]EdgeInfo
	in      map[GraphNode]EdgeInfo
	marks   LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *ParamNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *ParamNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *ParamNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *ParamNode) In() map[GraphNode]EdgeInfo { return a.in }

// SsaNode returns the ssa.Node the graph node models
func (a *ParamNode) SsaNode() *ssa.Parameter { return a.ssaNode }

// Type returns the type of the ssa node associated to the graph node
func (a *ParamNode) Type() types.Type { return a.ssaNode.Type() }

// Marks returns the location information of the node
func (a *ParamNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *ParamNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Position returns the estimated position of the node in the source
func (a *ParamNode) Position(c *State) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *ParamNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*ParamNode); ok {
		return a == a2
	}
	return false
}

// Index returns the parameter position of the node in the function's signature
func (a *ParamNode) Index() int { return a.argPos }

// ParentNode returns the node itself
func (a *ParamNode) ParentNode() GraphNode { return a }

// ParentName returns the name of the parent function
func (a *ParamNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.String()
	}
	return "ParamNode"
}

// LongID returns a string identifier for the node
func (a *ParamNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// FreeVarNode is a node that represents a free variable of the function (for closures)
type FreeVarNode struct {
	id      uint32
	parent  *SummaryGraph
	ssaNode *ssa.FreeVar
	fvPos   int
	out     map[GraphNode][]EdgeInfo
	in      map[GraphNode]EdgeInfo
	marks   LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *FreeVarNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *FreeVarNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *FreeVarNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *FreeVarNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *FreeVarNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *FreeVarNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// SsaNode returns the ssa.Node the graph node models
func (a *FreeVarNode) SsaNode() *ssa.FreeVar { return a.ssaNode }

// Type returns the type of the ssa node associated to the graph node
func (a *FreeVarNode) Type() types.Type { return a.ssaNode.Type() }

// Position returns the estimated position of the node in the source
func (a *FreeVarNode) Position(c *State) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *FreeVarNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*FreeVarNode); ok {
		return a == a2
	}
	return false
}

// Index returns the free variable position in the function's signature
func (a *FreeVarNode) Index() int { return a.fvPos }

// ParentName returns the name of the parent closure
func (a *FreeVarNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	}
	return "ParamNode"
}

// LongID returns a string identifier for the node
func (a *FreeVarNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// CallNodeArg is a node that represents the argument of a function call
type CallNodeArg struct {
	id       uint32
	parent   *CallNode
	ssaValue ssa.Value
	argPos   int
	out      map[GraphNode][]EdgeInfo
	in       map[GraphNode]EdgeInfo
	marks    LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *CallNodeArg) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *CallNodeArg) Graph() *SummaryGraph { return a.parent.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *CallNodeArg) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *CallNodeArg) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *CallNodeArg) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *CallNodeArg) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the ssa node associated to the graph node
func (a *CallNodeArg) Type() types.Type { return a.ssaValue.Type() }

// Position returns the estimated position of the node in the source
func (a *CallNodeArg) Position(c *State) token.Position {
	if a.parent != nil {
		return a.parent.Position(c)
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *CallNodeArg) Equal(node GraphNode) bool {
	if a2, ok := node.(*CallNodeArg); ok {
		return a == a2
	}
	return false
}

// ParentNode returns the parent call node
func (a *CallNodeArg) ParentNode() *CallNode { return a.parent }

// Index returns the argument's position in the parent call node
func (a *CallNodeArg) Index() int { return a.argPos }

// ParentName returns the name of the parent function (not the parent call node)
func (a *CallNodeArg) ParentName() string {
	if a.parent != nil && a.parent.parent != nil && a.parent.parent.Parent != nil {
		return a.parent.parent.Parent.String()
	}
	return "CallNodeArg"
}

// LongID returns a string identifier for the node
func (a *CallNodeArg) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// Value returns the ssa value of the call argument
func (a *CallNodeArg) Value() ssa.Value {
	return a.ssaValue
}

// CallNode is a node that represents a function call. It represents the Value returned by the function call
// and also points at the CallNodeArg nodes that are its arguments
type CallNode struct {
	id            uint32
	parent        *SummaryGraph
	callSite      ssa.CallInstruction
	callee        lang.CalleeInfo
	CalleeSummary *SummaryGraph
	args          []*CallNodeArg
	out           map[GraphNode][]EdgeInfo
	in            map[GraphNode]EdgeInfo
	marks         LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *CallNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *CallNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *CallNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *CallNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *CallNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *CallNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the call site (the type of the returned value, not the signature of the function called)
func (a *CallNode) Type() types.Type {
	if call, ok := a.callSite.(*ssa.Call); ok {
		return call.Type()
	}
	return nil
}

// Position returns the estimated position of the node in the source
func (a *CallNode) Position(c *State) token.Position {
	if a.callSite != nil && a.callSite.Common() != nil && a.callSite.Common().Value != nil {
		return c.Program.Fset.Position(a.callSite.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *CallNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*CallNode); ok {
		return a == a2
	}
	return false
}

// LongID returns a string identifier for the node
func (a *CallNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// ParentName returns the name of the parent function
func (a *CallNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	}
	return "CallNode"
}

// FindArg fins the node corresponding to the value v as an argument of the call
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

// Args returns the list of arguments of the call
func (a *CallNode) Args() []*CallNodeArg {
	return a.args
}

// FuncName returns the name of the function being called. It can be either the method name or a function name. The
// function could be a Value (and not a static call), in which case the name of the Value is returned.
func (a *CallNode) FuncName() string {
	if a.callSite != nil {
		if a.callSite.Common().IsInvoke() {
			return a.callSite.Common().Method.Name()
		}
		return a.callSite.Common().Value.Name()
	}
	return "<CallNode with nil callSite>"
}

// FuncString returns the string identified of the function being called. It can be either the method string or a
// function string. The function could be a Value (and not a static call), in which case the name of the Value
// is returned.
func (a *CallNode) FuncString() string {
	if a.callSite != nil {
		if a.callSite.Common().IsInvoke() {
			return a.callSite.Common().Method.String()
		}
		return a.callSite.Common().Value.String()
	}
	return "<CallNode with nil callSite>"

}

// A ReturnValNode is a node that represents a Value returned by a function
type ReturnValNode struct {
	id     uint32
	index  int // when a function returns a tuple, a return node represents a single indexed Value
	parent *SummaryGraph
	in     map[GraphNode]EdgeInfo
}

// Graph returns the parent summary graph of the node
func (a *ReturnValNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *ReturnValNode) Out() map[GraphNode][]EdgeInfo { return nil }

// ID returns the integer id of the node in its parent graph
func (a *ReturnValNode) ID() uint32 { return a.id }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *ReturnValNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *ReturnValNode) Marks() LocSet { return nil }

// SetLocs sets the locations information of the node
func (a *ReturnValNode) SetLocs(_ LocSet) {}

// Index returns the tuple index of the return node
func (a *ReturnValNode) Index() int { return a.index }

// Type returns the return type of the parent function
func (a *ReturnValNode) Type() types.Type {
	return lang.TryTupleIndexType(a.parent.ReturnType(), a.index)
}

// Position returns the estimated position of the node in the source
func (a *ReturnValNode) Position(c *State) token.Position {
	if a.parent != nil && a.parent.Parent != nil {
		return c.Program.Fset.Position(a.parent.Parent.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *ReturnValNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*ReturnValNode); ok {
		return a == a2
	}
	return false
}

// ParentName return the name of the parent function
func (a *ReturnValNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	}
	return "ReturnNode"
}

// LongID returns a string identifier for the node
func (a *ReturnValNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// ClosureNode represents a makeClosure instruction in the dataflow graph
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
	out       map[GraphNode][]EdgeInfo
	in        map[GraphNode]EdgeInfo
	marks     LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *ClosureNode) ID() uint32 { return a.id }

// Graph is the parent of a closure node is the summary of the function in which the closure is created.
func (a *ClosureNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *ClosureNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *ClosureNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the set of instructions through which data from the node flows
func (a *ClosureNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *ClosureNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the makeClosure instruction (the signature of the closure)
func (a *ClosureNode) Type() types.Type { return a.instr.Type() }

// Position returns the estimated position of the node in the source
func (a *ClosureNode) Position(c *State) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *ClosureNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*ClosureNode); ok {
		return a == a2
	}
	return false
}

// LongID returns a string identifier for the node
func (a *ClosureNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// Instr returns the makeClosure instruction corresponding to the closure node
func (a *ClosureNode) Instr() *ssa.MakeClosure {
	return a.instr
}

// ParentName returns the name of the function where the closure is created
func (a *ClosureNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	}
	return "CallNode"
}

// BoundVars returns the list of variables bound by the closure
func (a *ClosureNode) BoundVars() []*BoundVarNode {
	return a.boundVars
}

// FindBoundVar returns the BoundVarNode matching the input value v, if v is a bound variable of the closure
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

	// the ssaValue is the Value that corresponds to the bound variable in the SSA
	ssaValue ssa.Value

	// bPos is the position of the bound variable, and correspond to fvPos is the closure's summary
	bPos int

	out   map[GraphNode][]EdgeInfo
	in    map[GraphNode]EdgeInfo
	marks LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *BoundVarNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *BoundVarNode) Graph() *SummaryGraph { return a.parent.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *BoundVarNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *BoundVarNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *BoundVarNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *BoundVarNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the bound variable
func (a *BoundVarNode) Type() types.Type { return a.ssaValue.Type() }

// Value returns the ssa value of the bound variable
func (a *BoundVarNode) Value() ssa.Value { return a.ssaValue }

// Position returns the estimated position of the node in the source
func (a *BoundVarNode) Position(c *State) token.Position {
	if a.ssaValue != nil {
		return c.Program.Fset.Position(a.ssaValue.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *BoundVarNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*BoundVarNode); ok {
		return a == a2
	}
	return false
}

// Index returns the position of the bound variable in the make closure instruction. It will correspond to the
// position of the matching variable in the closure's free variables.
func (a *BoundVarNode) Index() int { return a.bPos }

// ParentNode returns the closure node corresponding to the bound variable
func (a *BoundVarNode) ParentNode() *ClosureNode { return a.parent }

// ParentName returns the name of the parent function (not the parent closure node)
func (a *BoundVarNode) ParentName() string {
	if a.parent != nil && a.parent.parent != nil && a.parent.parent.Parent != nil {
		return a.parent.parent.Parent.Name()
	}
	return "BoundVarNode"
}

// LongID returns a string identifier for the node
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
	out     map[GraphNode][]EdgeInfo
	in      map[GraphNode]EdgeInfo
	marks   LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *AccessGlobalNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *AccessGlobalNode) Graph() *SummaryGraph { return a.graph }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *AccessGlobalNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *AccessGlobalNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *AccessGlobalNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *AccessGlobalNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the
func (a *AccessGlobalNode) Type() types.Type { return a.Global.Type() }

// Position returns the estimated position of the node in the source
func (a *AccessGlobalNode) Position(c *State) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *AccessGlobalNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*AccessGlobalNode); ok {
		return a == a2
	}
	return false
}

// Instr returns the instruction that accesses the global
func (a *AccessGlobalNode) Instr() ssa.Instruction { return a.instr }

// ParentName returns the name of the function where the global is accessed
func (a *AccessGlobalNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

// LongID returns a string identifier for the node
func (a *AccessGlobalNode) LongID() string {
	return "#" + strconv.Itoa(int(a.graph.ID)) + "." + strconv.Itoa(int(a.id))
}

// A SyntheticNode can be used to represent any other type of node.
type SyntheticNode struct {
	id     uint32
	parent *SummaryGraph            // the parent of a SyntheticNode is the summary of the function in which it appears
	instr  ssa.Instruction          // a SyntheticNode must correspond to a specific instruction
	label  string                   // the label can be used to record information about synthetic nodes
	out    map[GraphNode][]EdgeInfo // the out maps the node to other nodes to which data flows
	in     map[GraphNode]EdgeInfo   // the in maps the node to other nodes from which data flows
	marks  LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *SyntheticNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *SyntheticNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *SyntheticNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *SyntheticNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *SyntheticNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *SyntheticNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the value the synthetic node abstracts
func (a *SyntheticNode) Type() types.Type {
	if val, ok := a.instr.(ssa.Value); ok {
		return val.Type()
	}
	return nil
}

// Position returns the estimated position of the node in the source
func (a *SyntheticNode) Position(c *State) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	}
	return lang.DummyPos
}

// Equal implements comparison for graph nodes
func (a *SyntheticNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*SyntheticNode); ok {
		return a == a2
	}
	return false
}

// Instr correspond to the instruction matching that synthetic node
func (a *SyntheticNode) Instr() ssa.Instruction { return a.instr }

// ParentName returns the name of the parent function of the synthetic node
func (a *SyntheticNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

// LongID returns a string identifier for the node
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
	out        map[GraphNode][]EdgeInfo // the out maps the node to other nodes to which data flows
	in         map[GraphNode]EdgeInfo   // the in maps the node to other nodes from which data flows
	marks      LocSet
}

// ID returns the integer id of the node in its parent graph
func (a *BoundLabelNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node
func (a *BoundLabelNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (a *BoundLabelNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (a *BoundLabelNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node
func (a *BoundLabelNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node
func (a *BoundLabelNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the bound label
func (a *BoundLabelNode) Type() types.Type { return a.targetInfo.Type() }

// Position returns the position of the bound label
func (a *BoundLabelNode) Position(c *State) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	}
	return lang.DummyPos
}

// Equal implements equality checking between bound label nodes
func (a *BoundLabelNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*BoundLabelNode); ok {
		return a == a2
	}
	return false
}

// Instr correspond to the instruction matching that synthetic node
func (a *BoundLabelNode) Instr() ssa.Instruction { return a.instr }

// DestInfo returns the information of the target bound variable
func (a *BoundLabelNode) DestInfo() BindingInfo { return a.targetInfo }

// Index returns the index of the bound variable in the closure
func (a *BoundLabelNode) Index() int { return a.targetInfo.BoundIndex }

// DestClosure returns the closure that binds the node
func (a *BoundLabelNode) DestClosure() *SummaryGraph { return a.targetAnon }

// SetDestClosure sets the closure that binds the node
func (a *BoundLabelNode) SetDestClosure(g *SummaryGraph) { a.targetAnon = g }

// ParentName returns the parent name of the bound label (its parent function)
func (a *BoundLabelNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

// LongID returns a string identifier for the node
func (a *BoundLabelNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// IfNode is used to track dataflow to if-statements (includes all types of branching).
// For now, this just contains the value that is being branched on (the if-condition).
type IfNode struct {
	id      uint32
	parent  *SummaryGraph            // the parent of an IfNode is the summary of the function in which it appears
	ssaNode *ssa.If                  // an IfNode must correspond to a specific instruction
	out     map[GraphNode][]EdgeInfo // the out maps the node to other nodes to which data flows
	in      map[GraphNode]EdgeInfo   // the in maps the node to other nodes from which data flows
	marks   LocSet
}

// ID returns the integer id of the node in its parent graph.
func (a *IfNode) ID() uint32 { return a.id }

// Graph returns the parent summary graph of the node.
func (a *IfNode) Graph() *SummaryGraph { return a.parent }

// Out returns the nodes the graph node's data flows to, with their object path.
func (a *IfNode) Out() map[GraphNode][]EdgeInfo { return a.out }

// In returns the nodes with incoming edges to the current node, with their object path.
func (a *IfNode) In() map[GraphNode]EdgeInfo { return a.in }

// Marks returns the location information of the node.
func (a *IfNode) Marks() LocSet { return a.marks }

// SetLocs sets the locations information of the node.
func (a *IfNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}

// Type returns the type of the value in the if-condition.
func (a *IfNode) Type() types.Type { return a.ssaNode.Cond.Type() }

// Position returns the position of the node.
func (a *IfNode) Position(c *State) token.Position {
	cond := a.ssaNode
	if cond == nil {
		return lang.DummyPos
	}

	pos := c.Program.Fset.Position(cond.Pos())
	if !pos.IsValid() {
		pos = c.Program.Fset.Position(cond.Cond.Pos())
	}

	return pos
}

// Equal implements equality checking between nodes.
func (a *IfNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*IfNode); ok {
		return a == a2
	}
	return false
}

// SsaNode returns the if-instruction.
func (a *IfNode) SsaNode() *ssa.If { return a.ssaNode }

// ParentName returns the name of the parent function.
func (a *IfNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	}
	return "IfNode"
}

// LongID returns a string identifier for the node.
func (a *IfNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}

// BuiltinCallNode is a node that represents a call to a builtin function. Builtin functions are handled separately
// because their data-flows are encoded directly in the analysis: they are not user-configurable summaries, and they
// are not analyzed.
// However, having an explicit node allows the dataflow analyses to use them sources, sanitizers or other analysis
// specific definitions.
type BuiltinCallNode struct {
	id       uint32
	parent   *SummaryGraph
	callSite ssa.CallInstruction
	name     string
	out      map[GraphNode][]EdgeInfo
	in       map[GraphNode]EdgeInfo
	marks    LocSet
}

// ID returns the integer id of the node in its parent graph
func (b *BuiltinCallNode) ID() uint32 { return b.id }

// LongID returns a string identifier for the node
func (b *BuiltinCallNode) LongID() string {
	return "#" + strconv.Itoa(int(b.parent.ID)) + "." + strconv.Itoa(int(b.id))
}

// Graph returns the parent summary graph of the node
func (b *BuiltinCallNode) Graph() *SummaryGraph { return b.parent }

// Out returns the nodes the graph node's data flows to, with their object path
func (b *BuiltinCallNode) Out() map[GraphNode][]EdgeInfo { return b.out }

// In returns the nodes with incoming edges to the current node, with their object path
func (b *BuiltinCallNode) In() map[GraphNode]EdgeInfo { return b.in }

// Marks returns the location information of the node
func (b *BuiltinCallNode) Marks() LocSet { return b.marks }

// SetLocs sets the locations information of the node
func (b *BuiltinCallNode) SetLocs(set LocSet) {
	if b.marks == nil {
		b.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(b.marks, set, funcutil.First[bool])
}

// FuncName is the name of the builtin called in the builtin call node
func (b *BuiltinCallNode) FuncName() string {
	return b.name
}

// Type returns the type of the result of the builtin call
func (b *BuiltinCallNode) Type() types.Type { return b.callSite.Value().Type() }

// Position returns the position of the node.
func (b *BuiltinCallNode) Position(c *State) token.Position {
	return c.Program.Fset.Position(b.callSite.Pos())
}

// Equal implements equality checking between nodes.
func (b *BuiltinCallNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*BuiltinCallNode); ok {
		return b == a2
	}
	return false
}

// ParentName returns the name of the parent function
func (b *BuiltinCallNode) ParentName() string {
	if b.parent != nil && b.parent.Parent != nil {
		return b.parent.Parent.String()
	}
	return "BuiltinCallNode"
}
