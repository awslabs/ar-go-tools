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
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

type LocSet = map[ssa.Instruction]bool

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

	// Type returns the type of the node
	Type() types.Type

	// Marks returns the loc-set of the node
	Marks() LocSet

	// SetLocs sets the loc-set of the node
	SetLocs(LocSet)

	// Equal lifts equality to the interface level
	Equal(GraphNode) bool
}

type IndexedGraphNode interface {
	// ParentNode returns the parent graph node of and indexed graph node, e.g. the CallNode of a call argument
	// or the ClosureNode of a bound variable. Returns itself for a ParamNode
	ParentNode() GraphNode

	// Index returns the position of the node in the parent node structure (argument or bound variable position)
	Index() int
}

func NodeKind(g GraphNode) string {
	switch g.(type) {
	case *ParamNode:
		return "Param  "
	case *CallNode:
		return "Call   "
	case *CallNodeArg:
		return "CallArg"
	case *ReturnValNode:
		return "RetVal "
	case *ClosureNode:
		return "Closure"
	case *BoundLabelNode:
		return "BoundLb"
	case *SyntheticNode:
		return "Synth  "
	case *BoundVarNode:
		return "BoundV "
	case *FreeVarNode:
		return "FreeV  "
	case *AccessGlobalNode:
		return "Global "
	}
	return ""
}

func NodeSummary(g GraphNode) string {
	switch x := g.(type) {
	case *ParamNode:
		return fmt.Sprintf("Parameter %q of %q", x.ssaNode.Name(), x.parent.Parent.Name())
	case *CallNode:
		return fmt.Sprintf("Result of call to %q", x.Callee().Name())
	case *CallNodeArg:
		return fmt.Sprintf("Argument %v in call to %q", x.Index(), x.ParentNode().Callee().Name())
	case *ReturnValNode:
		return fmt.Sprintf("Return value of %q", x.ParentName())
	case *ClosureNode:
		return fmt.Sprintf("Closure")
	case *BoundLabelNode:
		return fmt.Sprintf("Bound label")
	case *SyntheticNode:
		return fmt.Sprintf("Synthetic node")
	case *BoundVarNode:
		return "Bound variable"
	case *FreeVarNode:
		return "Free variable"
	case *AccessGlobalNode:
		return "Global "
	}
	return ""
}

// ParamNode is a node that represents a parameter of the function (input argument)
type ParamNode struct {
	id      uint32
	parent  *SummaryGraph
	ssaNode *ssa.Parameter
	argPos  int
	out     map[GraphNode]ObjectPath
	in      map[GraphNode]ObjectPath
	marks   LocSet
}

func (a *ParamNode) ID() uint32                    { return a.id }
func (a *ParamNode) Graph() *SummaryGraph          { return a.parent }
func (a *ParamNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *ParamNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *ParamNode) SsaNode() *ssa.Parameter       { return a.ssaNode }
func (a *ParamNode) Type() types.Type              { return a.ssaNode.Type() }
func (a *ParamNode) Marks() LocSet                 { return a.marks }
func (a *ParamNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
func (a *ParamNode) Position(c *AnalyzerState) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *ParamNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*ParamNode); ok {
		return a == a2
	}
	return false
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
	marks   LocSet
}

func (a *FreeVarNode) ID() uint32                    { return a.id }
func (a *FreeVarNode) Graph() *SummaryGraph          { return a.parent }
func (a *FreeVarNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *FreeVarNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *FreeVarNode) Marks() LocSet                 { return a.marks }
func (a *FreeVarNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
func (a *FreeVarNode) SsaNode() *ssa.FreeVar { return a.ssaNode }
func (a *FreeVarNode) Type() types.Type      { return a.ssaNode.Type() }

func (a *FreeVarNode) Position(c *AnalyzerState) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *FreeVarNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*FreeVarNode); ok {
		return a == a2
	}
	return false
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
	marks    LocSet
}

func (a *CallNodeArg) ID() uint32                    { return a.id }
func (a *CallNodeArg) Graph() *SummaryGraph          { return a.parent.parent }
func (a *CallNodeArg) Out() map[GraphNode]ObjectPath { return a.out }
func (a *CallNodeArg) In() map[GraphNode]ObjectPath  { return a.in }
func (a *CallNodeArg) Marks() LocSet                 { return a.marks }
func (a *CallNodeArg) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
func (a *CallNodeArg) Type() types.Type { return a.ssaValue.Type() }

func (a *CallNodeArg) Position(c *AnalyzerState) token.Position {
	if a.parent != nil {
		return a.parent.Position(c)
	} else {
		return lang.DummyPos
	}
}

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
	marks         LocSet
}

func (a *CallNode) ID() uint32                    { return a.id }
func (a *CallNode) Graph() *SummaryGraph          { return a.parent }
func (a *CallNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *CallNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *CallNode) Marks() LocSet                 { return a.marks }
func (a *CallNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
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

func (a *CallNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*CallNode); ok {
		return a == a2
	}
	return false
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
func (a *ReturnValNode) Marks() LocSet                 { return nil }
func (a *ReturnValNode) SetLocs(_ LocSet)              {}
func (a *ReturnValNode) Index() int                    { return a.index }
func (a *ReturnValNode) Type() types.Type              { return a.parent.ReturnType() }
func (a *ReturnValNode) Position(c *AnalyzerState) token.Position {
	if a.parent != nil && a.parent.Parent != nil {
		return c.Program.Fset.Position(a.parent.Parent.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *ReturnValNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*ReturnValNode); ok {
		return a == a2
	}
	return false
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
	marks     LocSet
}

func (a *ClosureNode) ID() uint32 { return a.id }

// Graph is the parent of a closure node is the summary of the function in which the closure is created.
func (a *ClosureNode) Graph() *SummaryGraph          { return a.parent }
func (a *ClosureNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *ClosureNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *ClosureNode) Marks() LocSet                 { return a.marks }
func (a *ClosureNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
func (a *ClosureNode) Type() types.Type { return a.instr.Type() }

func (a *ClosureNode) Position(c *AnalyzerState) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *ClosureNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*ClosureNode); ok {
		return a == a2
	}
	return false
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

	out   map[GraphNode]ObjectPath
	in    map[GraphNode]ObjectPath
	marks LocSet
}

func (a *BoundVarNode) ID() uint32                    { return a.id }
func (a *BoundVarNode) Graph() *SummaryGraph          { return a.parent.parent }
func (a *BoundVarNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *BoundVarNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *BoundVarNode) Marks() LocSet                 { return a.marks }
func (a *BoundVarNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
func (a *BoundVarNode) Type() types.Type { return a.ssaValue.Type() }
func (a *BoundVarNode) Value() ssa.Value { return a.ssaValue }

func (a *BoundVarNode) Position(c *AnalyzerState) token.Position {
	if a.ssaValue != nil {
		return c.Program.Fset.Position(a.ssaValue.Pos())
	} else {
		return lang.DummyPos
	}
}

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
	marks   LocSet
}

func (a *AccessGlobalNode) ID() uint32                    { return a.id }
func (a *AccessGlobalNode) Graph() *SummaryGraph          { return a.graph }
func (a *AccessGlobalNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *AccessGlobalNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *AccessGlobalNode) Marks() LocSet                 { return a.marks }
func (a *AccessGlobalNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
func (a *AccessGlobalNode) Type() types.Type { return a.Global.Type() }

func (a *AccessGlobalNode) Position(c *AnalyzerState) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *AccessGlobalNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*AccessGlobalNode); ok {
		return a == a2
	}
	return false
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
	marks  LocSet
}

func (a *SyntheticNode) ID() uint32                    { return a.id }
func (a *SyntheticNode) Graph() *SummaryGraph          { return a.parent }
func (a *SyntheticNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *SyntheticNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *SyntheticNode) Marks() LocSet                 { return a.marks }
func (a *SyntheticNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
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

func (a *SyntheticNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*SyntheticNode); ok {
		return a == a2
	}
	return false
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
	marks      LocSet
}

func (a *BoundLabelNode) ID() uint32                    { return a.id }
func (a *BoundLabelNode) Graph() *SummaryGraph          { return a.parent }
func (a *BoundLabelNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *BoundLabelNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *BoundLabelNode) Marks() LocSet                 { return a.marks }
func (a *BoundLabelNode) SetLocs(set LocSet) {
	if a.marks == nil {
		a.marks = map[ssa.Instruction]bool{}
	}
	funcutil.Merge(a.marks, set, funcutil.First[bool])
}
func (a *BoundLabelNode) Type() types.Type { return a.targetInfo.Type() }

func (a *BoundLabelNode) Position(c *AnalyzerState) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return lang.DummyPos
	}
}

func (a *BoundLabelNode) Equal(node GraphNode) bool {
	if a2, ok := node.(*BoundLabelNode); ok {
		return a == a2
	}
	return false
}

// Instr correspond to the instruction matching that synthetic node
func (a *BoundLabelNode) Instr() ssa.Instruction { return a.instr }

func (a *BoundLabelNode) DestInfo() BindingInfo { return a.targetInfo }

func (a *BoundLabelNode) Index() int { return a.targetInfo.BoundIndex }

func (a *BoundLabelNode) DestClosure() *SummaryGraph { return a.targetAnon }

func (a *BoundLabelNode) SetDestClosure(g *SummaryGraph) { a.targetAnon = g }

func (a *BoundLabelNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

func (a *BoundLabelNode) LongID() string {
	return "#" + strconv.Itoa(int(a.parent.ID)) + "." + strconv.Itoa(int(a.id))
}
