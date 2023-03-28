package dataflow

import (
	"fmt"
	"go/token"
	"io"
	"os"
	"strings"

	"github.com/awslabs/argot/analysis/functional"
	"github.com/awslabs/argot/analysis/packagescan"
	"github.com/awslabs/argot/analysis/ssafuncs"
	"github.com/awslabs/argot/analysis/summaries"
	"golang.org/x/tools/go/ssa"
)

// ObjectPath contains information relative to the object pointed to.
type ObjectPath struct {
	// RelPath is the relative object memory path, e.g. * for dereference TODO: use this for field/tuple sensitivity
	RelPath string

	// Cond is the condition under which this pointer/edge is valid.
	// An example usage is in the implementation of validators.
	Cond *ConditionInfo
}

// Graph Nodes

// GraphNode represents nodes in the function summary graph.
// Those nodes are either input argument nodes, callgraph nodes, call arguments nodes or return nodes.
type GraphNode interface {
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
	Position(c *Cache) token.Position

	String() string
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
	parent  *SummaryGraph
	ssaNode *ssa.Parameter
	argPos  int
	out     map[GraphNode]ObjectPath
	in      map[GraphNode]ObjectPath
}

func (a *ParamNode) Graph() *SummaryGraph          { return a.parent }
func (a *ParamNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *ParamNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *ParamNode) SsaNode() *ssa.Parameter       { return a.ssaNode }

func (a *ParamNode) Position(c *Cache) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	} else {
		return packagescan.DummyPos
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

// FreeVarNode is a node that represents a free variable of the function (for closures)
type FreeVarNode struct {
	parent  *SummaryGraph
	ssaNode *ssa.FreeVar
	fvPos   int
	out     map[GraphNode]ObjectPath
	in      map[GraphNode]ObjectPath
}

func (a *FreeVarNode) Graph() *SummaryGraph          { return a.parent }
func (a *FreeVarNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *FreeVarNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *FreeVarNode) SsaNode() *ssa.FreeVar         { return a.ssaNode }

func (a *FreeVarNode) Position(c *Cache) token.Position {
	if a.ssaNode != nil {
		return c.Program.Fset.Position(a.ssaNode.Pos())
	} else {
		return packagescan.DummyPos
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

// CallNodeArg is a node that represents the argument of a function call
type CallNodeArg struct {
	parent   *CallNode
	ssaValue ssa.Value
	argPos   int
	out      map[GraphNode]ObjectPath
	in       map[GraphNode]ObjectPath
}

func (a *CallNodeArg) Graph() *SummaryGraph          { return a.parent.parent }
func (a *CallNodeArg) Out() map[GraphNode]ObjectPath { return a.out }
func (a *CallNodeArg) In() map[GraphNode]ObjectPath  { return a.in }

func (a *CallNodeArg) Position(c *Cache) token.Position {
	if a.ssaValue != nil {
		return c.Program.Fset.Position(a.ssaValue.Pos())
	} else {
		return packagescan.DummyPos
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

// CallNode is a node that represents a function call. It represents the value returned by the function call
// and also points at the CallNodeArg nodes that are its arguments
type CallNode struct {
	parent        *SummaryGraph
	callSite      ssa.CallInstruction
	callee        CalleeInfo
	CalleeSummary *SummaryGraph
	args          []*CallNodeArg
	out           map[GraphNode]ObjectPath
	in            map[GraphNode]ObjectPath
}

func (a *CallNode) Graph() *SummaryGraph          { return a.parent }
func (a *CallNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *CallNode) In() map[GraphNode]ObjectPath  { return a.in }

func (a *CallNode) Position(c *Cache) token.Position {
	if a.callSite != nil && a.callSite.Common() != nil && a.callSite.Common().Value != nil {
		return c.Program.Fset.Position(a.callSite.Pos())
	} else {
		return packagescan.DummyPos
	}
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

// A ReturnNode is a node that represents a node where the function returns.
type ReturnNode struct {
	parent *SummaryGraph
	in     map[GraphNode]ObjectPath
}

func (a *ReturnNode) Graph() *SummaryGraph          { return a.parent }
func (a *ReturnNode) Out() map[GraphNode]ObjectPath { return nil }
func (a *ReturnNode) In() map[GraphNode]ObjectPath  { return a.in }
func (a *ReturnNode) Position(c *Cache) token.Position {
	if a.parent != nil && a.parent.Parent != nil {
		return c.Program.Fset.Position(a.parent.Parent.Pos())
	} else {
		return packagescan.DummyPos
	}
}

func (a *ReturnNode) ParentName() string {
	if a.parent != nil && a.parent.Parent != nil {
		return a.parent.Parent.Name()
	} else {
		return "ReturnNode"
	}
}

type ClosureNode struct {
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

// Graph is the parent of a closure node is the summary of the function in which the closure is created.
func (a *ClosureNode) Graph() *SummaryGraph          { return a.parent }
func (a *ClosureNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *ClosureNode) In() map[GraphNode]ObjectPath  { return a.in }

func (a *ClosureNode) Position(c *Cache) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return packagescan.DummyPos
	}
}

// Instr retruns the makeClosure instruction corresponding to the closure node
func (a *ClosureNode) Instr() *ssa.MakeClosure { return a.instr }

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
	// the parent is the closure node that captures the variables
	parent *ClosureNode

	// the ssaValue is the value that corresponds to the bound variable in the SSA
	ssaValue ssa.Value

	// bPos is the position of the bound variable, and correspond to fvPos is the closure's summary
	bPos int

	out map[GraphNode]ObjectPath
	in  map[GraphNode]ObjectPath
}

func (a *BoundVarNode) Graph() *SummaryGraph          { return a.parent.parent }
func (a *BoundVarNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *BoundVarNode) In() map[GraphNode]ObjectPath  { return a.in }

func (a *BoundVarNode) Position(c *Cache) token.Position {
	if a.ssaValue != nil {
		return c.Program.Fset.Position(a.ssaValue.Pos())
	} else {
		return packagescan.DummyPos
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

// A AccessGlobalNode represents a node where a global variable is accessed (read or written)
// In this context, a "write" is when data flows to the node, and a "read" is when data flows from the node
type AccessGlobalNode struct {
	IsWrite bool            // IsWrite is true if the global is written at that location
	graph   *SummaryGraph   // the parent graph in which the read/write occurs
	instr   ssa.Instruction // the instruction where the global is read/written to
	Global  *GlobalNode     // the corresponding global node
	out     map[GraphNode]ObjectPath
	in      map[GraphNode]ObjectPath
}

func (a *AccessGlobalNode) Graph() *SummaryGraph          { return a.graph }
func (a *AccessGlobalNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *AccessGlobalNode) In() map[GraphNode]ObjectPath  { return a.in }

func (a *AccessGlobalNode) Position(c *Cache) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return packagescan.DummyPos
	}
}

func (a *AccessGlobalNode) Instr() ssa.Instruction { return a.instr }

func (a *AccessGlobalNode) ParentName() string {
	if a.instr != nil {
		return a.instr.Parent().Name()
	}
	return ""
}

// A SyntheticNode can be used to represent any other type of node.
type SyntheticNode struct {
	parent *SummaryGraph            // the parent of a SyntheticNode is the summary of the function in which it appears
	instr  ssa.Instruction          // a SyntheticNode must correspond to a specific instruction
	label  string                   // the label can be used to record information about synthetic nodes
	out    map[GraphNode]ObjectPath // the out maps the node to other nodes to which data flows
	in     map[GraphNode]ObjectPath // the in maps the node to other nodes from which data flows
}

func (a *SyntheticNode) Graph() *SummaryGraph          { return a.parent }
func (a *SyntheticNode) Out() map[GraphNode]ObjectPath { return a.out }
func (a *SyntheticNode) In() map[GraphNode]ObjectPath  { return a.in }

func (a *SyntheticNode) Position(c *Cache) token.Position {
	if a.instr != nil {
		return c.Program.Fset.Position(a.instr.Pos())
	} else {
		return packagescan.DummyPos
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

// Graph

// SummaryGraph is the function dataflow summary graph.
type SummaryGraph struct {
	Constructed         bool                                                // true if summary graph is Constructed, false if it is a dummy
	IsInterfaceContract bool                                                // true if the summary is built from an interface's dataflow contract
	Parent              *ssa.Function                                       // the ssa function it summarizes
	Params              map[ssa.Node]*ParamNode                             // the parameters of the function, associated to ParamNode
	FreeVars            map[ssa.Node]*FreeVarNode                           // the free variables of the function, associated to FreeVarNode
	Callsites           map[ssa.CallInstruction]*CallNode                   // the call sites of the function
	Callees             map[ssa.CallInstruction]map[*ssa.Function]*CallNode // the call instructions are linked to CallNode.

	CreatedClosures       map[ssa.Instruction]*ClosureNode                    // the MakeClosure nodes in the function  are linked to ClosureNode
	ReferringMakeClosures map[ssa.Instruction]*ClosureNode                    // the MakeClosure nodes referring to this function
	SyntheticNodes        map[ssa.Instruction]*SyntheticNode                  // the synthetic nodes of the function
	AccessGlobalNodes     map[ssa.Instruction]map[ssa.Value]*AccessGlobalNode // the nodes accessing global information
	Returns               map[ssa.Instruction]*ReturnNode                     // the return instructions are linked to ReturnNode
	errors                map[error]bool
}

// NewSummaryGraph builds a new summary graph given a function and its corresponding node.
// Returns a non-nil value if and only if f is non-nil.
// If non-nil, the returned summary graph is marked as not constructed.
func NewSummaryGraph(f *ssa.Function) *SummaryGraph {
	if f == nil {
		return nil
	}
	g := &SummaryGraph{
		Constructed:           false,
		IsInterfaceContract:   false,
		Parent:                f,
		Params:                make(map[ssa.Node]*ParamNode, len(f.Params)),
		FreeVars:              make(map[ssa.Node]*FreeVarNode, len(f.FreeVars)),
		Callees:               make(map[ssa.CallInstruction]map[*ssa.Function]*CallNode),
		Callsites:             make(map[ssa.CallInstruction]*CallNode),
		Returns:               make(map[ssa.Instruction]*ReturnNode),
		CreatedClosures:       make(map[ssa.Instruction]*ClosureNode),
		ReferringMakeClosures: make(map[ssa.Instruction]*ClosureNode),
		AccessGlobalNodes:     make(map[ssa.Instruction]map[ssa.Value]*AccessGlobalNode),
		SyntheticNodes:        make(map[ssa.Instruction]*SyntheticNode),
		errors:                map[error]bool{},
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
	// A single return node, but map tracks possible return paths
	returnNode := &ReturnNode{parent: g}
	for _, block := range f.Blocks {
		last := ssafuncs.LastInstr(block)
		if last != nil {
			retInstr, isReturn := last.(*ssa.Return)
			if isReturn {
				g.addReturn(retInstr, returnNode)
			}
		}
	}

	return g
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
		parent:  g,
		ssaNode: param,
		out:     make(map[GraphNode]ObjectPath),
		in:      make(map[GraphNode]ObjectPath),
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
		parent:  g,
		ssaNode: fv,
		out:     make(map[GraphNode]ObjectPath),
		in:      make(map[GraphNode]ObjectPath),
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

// AddCallInstr adds a call site to the summary from a call instruction (use when no call graph is available)
// @requires g != nil
func (g *SummaryGraph) AddCallInstr(c *Cache, instr ssa.CallInstruction) {
	// Already seen this instruction? Multiple calls of this function will not gather more information.
	if _, ok := g.Callees[instr]; ok {
		return
	}

	args := ssafuncs.GetArgs(instr)
	callees, err := c.ResolveCallee(instr)
	if err != nil {
		c.Logger.Fatalf("missing information in cache (%s), could not resolve callee in instruction %s", err,
			instr.String())
	}
	// Add each callee as a node for this call instruction
	for _, callee := range callees {
		node := &CallNode{
			parent:   g,
			callee:   callee,
			args:     make([]*CallNodeArg, len(args)),
			callSite: instr,
			out:      make(map[GraphNode]ObjectPath),
			in:       make(map[GraphNode]ObjectPath),
		}

		for pos, arg := range args {
			argNode := &CallNodeArg{
				parent:   node,
				ssaValue: arg,
				argPos:   pos,
				out:      make(map[GraphNode]ObjectPath),
				in:       make(map[GraphNode]ObjectPath),
			}
			node.args[pos] = argNode
		}
		g.addCallNode(node)
	}

	if len(callees) == 0 {

		// TODO: remove that when we have a method to resolve all callees
		node := &CallNode{
			parent:   g,
			callee:   CalleeInfo{},
			args:     make([]*CallNodeArg, len(args)),
			callSite: instr,
			out:      make(map[GraphNode]ObjectPath),
			in:       make(map[GraphNode]ObjectPath),
		}

		for pos, arg := range args {
			argNode := &CallNodeArg{
				parent:   node,
				ssaValue: arg,
				out:      make(map[GraphNode]ObjectPath),
				in:       make(map[GraphNode]ObjectPath),
			}
			node.args[pos] = argNode
		}
		g.addCallNode(node)
	}
}

// addReturn adds a return node to the summary
// @requires g != nil
func (g *SummaryGraph) addReturn(instr ssa.Instruction, node *ReturnNode) {
	if _, ok := g.Returns[instr]; !ok {
		g.Returns[instr] = node
	}
}

// AddClosure adds a closure node to the summary
// @requires g != nil
func (g *SummaryGraph) AddClosure(x *ssa.MakeClosure) {
	if _, ok := g.CreatedClosures[x]; ok {
		return
	}

	node := &ClosureNode{
		parent:         g,
		ClosureSummary: nil,
		instr:          x,
		boundVars:      []*BoundVarNode{},
		out:            make(map[GraphNode]ObjectPath),
		in:             make(map[GraphNode]ObjectPath),
	}

	g.CreatedClosures[x] = node

	for pos, binding := range x.Bindings {
		bindingNode := &BoundVarNode{
			parent:   node,
			ssaValue: binding,
			bPos:     pos,
			out:      make(map[GraphNode]ObjectPath),
			in:       make(map[GraphNode]ObjectPath),
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
			IsWrite: false,
			graph:   g,
			instr:   instr,
			Global:  global,
			out:     make(map[GraphNode]ObjectPath),
			in:      make(map[GraphNode]ObjectPath),
		}
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
			parent: g,
			instr:  instr,
			label:  label,
			out:    make(map[GraphNode]ObjectPath),
			in:     make(map[GraphNode]ObjectPath),
		}
		g.SyntheticNodes[instr] = node
	}
}

func (g *SummaryGraph) AddSyntheticNodeEdge(mark Mark, instr ssa.Instruction, label string, info *ConditionInfo) {
	node, ok := g.SyntheticNodes[instr]
	if !ok {
		return
	}
	g.addEdge(mark, node, info)
}

// Functions to add edges to the graph

// addEdge adds an edge between source and dest in the summary graph g.
// @requires g != nil
func (g *SummaryGraph) addEdge(source Mark, dest GraphNode, info *ConditionInfo) {
	// This function's goal is to define how the source of an edge is obtained in the summary given a Mark that
	// is produced in the intra-procedural analysis.

	if source.IsParameter() {
		if sourceArgNode, ok := g.Params[source.Node]; ok && sourceArgNode != dest {
			sourceArgNode.out[dest] = ObjectPath{source.RegionPath, info}
			addInEdge(dest, sourceArgNode, ObjectPath{source.RegionPath, info})
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
					sourceCallArgNode.out[dest] = ObjectPath{source.RegionPath, info}
					addInEdge(dest, sourceCallArgNode, ObjectPath{source.RegionPath, info})
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
					sourceNode.out[dest] = ObjectPath{source.RegionPath, info}
					addInEdge(dest, sourceNode, ObjectPath{source.RegionPath, info})
				}
			}

		}
	}

	if source.IsFreeVar() {
		if sourceFreeVarNode, ok := g.FreeVars[source.Node]; ok && sourceFreeVarNode != dest {
			sourceFreeVarNode.out[dest] = ObjectPath{source.RegionPath, info}
			addInEdge(dest, sourceFreeVarNode, ObjectPath{source.RegionPath, info})
		}
	}

	if source.IsBoundVar() {
		// A bound var source's node must be a make closure node
		sourceClosure := source.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[sourceClosure]; ok {
			bvNode := cNode.FindBoundVar(source.Qualifier)
			if bvNode != nil && bvNode != dest {
				bvNode.out[dest] = ObjectPath{source.RegionPath, info}
				addInEdge(dest, bvNode, ObjectPath{source.RegionPath, info})
			}
		}
	}

	if source.IsClosure() {
		sourceClosure := source.Node.(ssa.Instruction)
		if cNode, ok := g.CreatedClosures[sourceClosure]; ok {
			if cNode != dest {
				cNode.out[dest] = ObjectPath{source.RegionPath, info}
				addInEdge(dest, cNode, ObjectPath{source.RegionPath, info})
			}
		}
	}

	if source.IsSynthetic() {
		// A synthetic source can refer to any instruction
		sourceInstr := source.Node.(ssa.Instruction)
		if sourceNode, ok := g.SyntheticNodes[sourceInstr]; ok {
			if sourceNode != dest {
				sourceNode.out[dest] = ObjectPath{source.RegionPath, info}
				addInEdge(dest, sourceNode, ObjectPath{source.RegionPath, info})
			}
		}
	}

	if source.IsGlobal() {
		sourceInstr := source.Node.(ssa.Instruction)
		if group, ok := g.AccessGlobalNodes[sourceInstr]; ok {
			if sourceNode, ok := group[source.Qualifier]; ok {
				sourceNode.out[dest] = ObjectPath{source.RegionPath, info}
				addInEdge(dest, sourceNode, ObjectPath{source.RegionPath, info})
			}
		}
	}
}

// AddCallArgEdge adds an edge in the summary from a mark to a function call argument.
// @requires g != nil
func (g *SummaryGraph) AddCallArgEdge(mark Mark, call ssa.CallInstruction, arg ssa.Value, cond *ConditionInfo) {
	callNodes := g.Callees[call]
	if callNodes == nil {
		g.addError(fmt.Errorf("attempting to set call arg edge but no call node for %s", call))
		os.Exit(1)
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
		g.addError(fmt.Errorf("attempting to set call arg edge but no call node for %s", call))
		os.Exit(1)
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
		os.Exit(1)
		return
	}

	boundVarNode := closureNode.FindBoundVar(v)
	if boundVarNode == nil {
		g.addError(fmt.Errorf("attempting to set call arg edge but no call arg node"))
		return
	}
	g.addEdge(mark, boundVarNode, cond)

}

// AddReturnEdge adds an edge in the summary from the mark to a return instruction
// @requires g != nil
func (g *SummaryGraph) AddReturnEdge(mark Mark, retInstr ssa.Instruction, cond *ConditionInfo) {
	retNode := g.Returns[retInstr]

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
	case *ReturnNode:
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
	default:
		panic(fmt.Sprintf("invalid dest node type: %T", dest))
	}
}

// Loading function summaries from predefined summaries

// addParamEdgeByPos adds an edge between the arguments at position src and dest in the summary graph.
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
			srcArg.out[destArg] = ObjectPath{"", nil}

			if destArg.in == nil {
				destArg.in = make(map[GraphNode]ObjectPath)
			}
			destArg.in[srcArg] = ObjectPath{"", nil}
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

// addReturnEdgeByPos adds an edge between the parameter at position src to the returned tuple position dest.
// The tuple position is simply ignored.
// TODO: change this when we support tracking tuple indexes.
func (g *SummaryGraph) addReturnEdgeByPos(src int, _ int) bool {
	if src < 0 || src >= len(g.Parent.Params) {
		return false
	}
	srcNode := g.Parent.Params[src]
	if srcNode == nil {
		return false
	}

	if srcArg, ok := g.Params[srcNode]; ok {
		// Add edge to any return
		for _, retNode := range g.Returns {
			srcArg.out[retNode] = ObjectPath{"", nil}
			if retNode.in == nil {
				retNode.in = make(map[GraphNode]ObjectPath)
			}
			retNode.in[srcArg] = ObjectPath{"", nil}
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
func LoadPredefinedSummary(f *ssa.Function) *SummaryGraph {
	preDef, ok := summaries.SummaryOfFunc(f)
	if !ok {
		return nil
	}
	summaryBase := NewSummaryGraph(f)
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
		return fmt.Sprintf("\"%s of %s [%d]\"", a.SsaNode().String(), fname, a.Index())
	}
}

func (a *CallNodeArg) String() string {
	return fmt.Sprintf("\"%s @arg:%s [%d]\"",
		strings.Trim(a.ParentNode().String(), "\""),
		a.ssaValue.Name(), a.Index())
}

func (a *CallNode) String() string {
	return fmt.Sprintf("\"(%s)call: %s in %s\"", a.callee.Type.Code(), a.callSite.String(), a.callSite.Parent().Name())
}

func (a *ReturnNode) String() string {
	return fmt.Sprintf("\"%s.return\"", a.parent.Parent.Name())
}

func (a *SyntheticNode) String() string {
	return fmt.Sprintf("\"synthetic: %s = %s\"", a.instr.(ssa.Value).Name(), a.instr.String())
}

func (a *FreeVarNode) String() string {
	return fmt.Sprintf("\"freevar:%s\"", a.ssaNode.Name())
}

func (a *BoundVarNode) String() string {
	return fmt.Sprintf("\"boundvar:%s\"", a.ssaValue.String())
}

func (a *ClosureNode) String() string {
	return fmt.Sprintf("\"closure:%s\"", a.instr.String())
}

func (a *AccessGlobalNode) String() string {
	typ := "read"
	if a.IsWrite {
		typ = "write"
	}
	return fmt.Sprintf("\"global:%s in %s (%s)\"", a.Global.value.String(), a.instr.String(), typ)
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
			for n := range callN.Out() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(callN.String()), escape(n.String()))
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

	for _, r := range g.Returns {
		for n := range r.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", escape(r.String()), escape(n.String()))
		}
		if !outEdgesOnly {
			for n := range r.In() {
				fmt.Fprintf(w, "\t%s -> %s;\n", escape(r.String()), escape(n.String()))
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

	for _, r := range g.Returns {
		ppNodes("Return", w, r, outEdgesOnly)
	}

	for _, s := range g.SyntheticNodes {
		ppNodes("Synthetic", w, s, outEdgesOnly)
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
	if c.Cond != nil && len(c.Cond.Conditions) > 0 {
		fmt.Fprintf(w, "    ?%s %s %s\n", c.Cond.String(), arrow, n.String())
	} else {
		fmt.Fprintf(w, "    %s %s\n", arrow, n.String())
	}
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

	for _, r := range g.Returns {
		f(r)
	}

	for _, s := range g.SyntheticNodes {
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

	args := strings.Join(functional.Map(a.Args(), func(cg *CallNodeArg) string { return cg.String() }), ",")
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
