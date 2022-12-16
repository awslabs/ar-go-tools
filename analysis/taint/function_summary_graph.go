package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/taint/summaries"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"io"
	"os"
)

type objectPath = string

// Graph Nodes

// GraphNode represents nodes in the function summary graph
// Those nodes are either input argument nodes, callgraph nodes, call arguments nodes or return nodes
type GraphNode interface {
	Graph() *SummaryGraph
	Out() map[GraphNode]objectPath
	ParentName() string
	Position() token.Position
	String() string
	IsSink(config *config.Config) bool
}

// ParamNode is a node that represents a parameter of the function (input argument)
type ParamNode struct {
	parent  *SummaryGraph
	ssaNode *ssa.Parameter
	argPos  int
	out     map[GraphNode]objectPath
}

func (a *ParamNode) Graph() *SummaryGraph          { return a.parent }
func (a *ParamNode) Out() map[GraphNode]objectPath { return a.out }
func (a *ParamNode) Position() token.Position      { return analysis.SafeValuePos(a.ssaNode) }
func (a *ParamNode) ParentName() string {
	if a.parent != nil && a.parent.parent != nil {
		return a.parent.parent.Name()
	} else {
		return "ParamNode"
	}
}
func (a *ParamNode) IsSink(_ *config.Config) bool {
	// A Parameter node is never a sink; the sink will be identified at the call site, not the callee definition.
	return false
}

// CallNodeArg is a node that represents the argument of a function call
type CallNodeArg struct {
	parent   *CallNode
	ssaValue ssa.Value
	argPos   int
	out      map[GraphNode]objectPath
}

func (a *CallNodeArg) Graph() *SummaryGraph          { return a.parent.parent }
func (a *CallNodeArg) Out() map[GraphNode]objectPath { return a.out }
func (a *CallNodeArg) Position() token.Position      { return analysis.SafeValuePos(a.ssaValue) }
func (a *CallNodeArg) ParentName() string {
	if a.parent != nil && a.parent.parent != nil && a.parent.parent.parent != nil {
		return a.parent.parent.parent.Name()
	} else {
		return "CallNodeArg"
	}
}
func (a *CallNodeArg) IsSink(config *config.Config) bool {
	// A call node argument is a sink if the callee is a sink
	return a.parent.IsSink(config)
}

// CallNode is a node that represents a function call. It represents the value returned by the function call
// and also points at the CallNodeArg nodes that are its arguments
type CallNode struct {
	parent        *SummaryGraph
	callSite      ssa.CallInstruction
	callee        *ssa.Function
	calleeSummary *SummaryGraph
	args          []*CallNodeArg
	out           map[GraphNode]objectPath
}

func (a *CallNode) Graph() *SummaryGraph          { return a.parent }
func (a *CallNode) Out() map[GraphNode]objectPath { return a.out }

func (a *CallNode) Position() token.Position {
	if a.callSite != nil {
		return analysis.SafeValuePos(a.callSite.Common().Value)
	} else {
		return analysis.DummyPos
	}

}

func (a *CallNode) ParentName() string {
	if a.parent != nil && a.parent.parent != nil {
		return a.parent.parent.Name()
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
func (a *CallNode) IsSink(config *config.Config) bool {
	return isSinkNode(config, a.callSite.(ssa.Node))
}

func (a *CallNode) FuncName() string {
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
}

func (a *ReturnNode) Graph() *SummaryGraph          { return a.parent }
func (a *ReturnNode) Out() map[GraphNode]objectPath { return nil }
func (a *ReturnNode) Position() token.Position      { return analysis.SafeFunctionPos(a.parent.parent) }
func (a *ReturnNode) ParentName() string {
	if a.parent != nil && a.parent.parent != nil {
		return a.parent.parent.Name()
	} else {
		return "ReturnNode"
	}
}
func (a *ReturnNode) IsSink(_ *config.Config) bool {
	// A return node is never a sink node
	return false
}

// Graph

// SummaryGraph is the function dataflow summary graph.
type SummaryGraph struct {
	constructed bool                                // true if summary graph is constructed, false if it is a dummy
	parent      *ssa.Function                       // the ssa function it summarizes
	params      map[ssa.Node]*ParamNode             // the parameters of the function, associated to ParamNode
	callsites   map[ssa.CallInstruction]*CallNode   // the call sites of the function
	callees     map[ssa.CallInstruction][]*CallNode // the call instructions are linked to CallNode.
	// A call site can have multiple callees
	returns map[ssa.Instruction]*ReturnNode // the return instructions are linked to ReturnNode
}

// NewSummaryGraph builds a new summary graph given a function and its corresponding node.
// cg may be nil.
// Returns a non-nil value if and only if f is non-nil.
// If non-nil, the returned summary graph is marked as not constructed.
func NewSummaryGraph(f *ssa.Function, cg *callgraph.Node) *SummaryGraph {
	if f == nil {
		return nil
	}
	g := &SummaryGraph{
		constructed: false,
		parent:      f,
		params:      make(map[ssa.Node]*ParamNode, len(f.Params)),
		callees:     make(map[ssa.CallInstruction][]*CallNode),
		callsites:   make(map[ssa.CallInstruction]*CallNode),
		returns:     nil,
	}
	// Add the parameters
	for pos, param := range f.Params {
		g.addParam(param, pos)
	}
	// Add return instructions
	g.returns = make(map[ssa.Instruction]*ReturnNode)
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

	if cg != nil {
		for _, called := range cg.Out {
			g.addCallee(called)
		}
	}
	return g
}

// addError adds an error to the summary graph. Can be modified to change the behavior when an error is encountered
// when building the summary
func (g *SummaryGraph) addError(e error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", e.Error())
}

// Functions to add nodes to the graph

// addParam adds a parameter to the summary
// @requires g != nil
func (g *SummaryGraph) addParam(param *ssa.Parameter, pos int) {
	if param == nil {
		return
	}

	node := &ParamNode{
		parent:  g,
		ssaNode: param,
		out:     make(map[GraphNode]objectPath),
		argPos:  pos,
	}
	g.params[param] = node
}

// containsCallNode returns true if nodes contains node, otherwise false
func containsCallNode(nodes []*CallNode, node *CallNode) bool {
	// The number of nodes in a call is expected to be small
	for _, x := range nodes {
		if x.callee == node.callee {
			return true
		}
	}
	return false
}

// addCallNode adds a call site to the summary
// @requires g != nil
func (g *SummaryGraph) addCallNode(node *CallNode) bool {
	if callNodes, ok := g.callees[node.callSite]; ok {
		if containsCallNode(callNodes, node) {
			return false
		}
		g.callees[node.callSite] = append(callNodes, node)
	} else {
		g.callees[node.callSite] = []*CallNode{node}
	}
	return true
}

// addCallee adds a call site to the summary from a callgraph edge
// @requires g != nil
func (g *SummaryGraph) addCallee(edge *callgraph.Edge) {
	if edge == nil || edge.Site == nil {
		return
	}

	args := ssafuncs.GetArgs(edge.Site)

	node := &CallNode{
		parent:   g,
		callee:   edge.Callee.Func,
		args:     make([]*CallNodeArg, len(args)),
		callSite: edge.Site,
		out:      make(map[GraphNode]objectPath),
	}

	for pos, arg := range args {
		argNode := &CallNodeArg{
			parent:   node,
			ssaValue: arg,
			argPos:   pos,
			out:      make(map[GraphNode]objectPath),
		}
		node.args[pos] = argNode
	}

	g.addCallNode(node)
}

// addCallInstr adds a call site to the summary from a call instruction (use when no call graph is available)
// @requires g != nil
func (g *SummaryGraph) addCallInstr(c *analysis.Cache, instr ssa.CallInstruction) {
	// Already seen this instruction? Multiple calls of this function will not gather more information.
	if _, ok := g.callees[instr]; ok {
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
			out:      make(map[GraphNode]objectPath),
		}

		for pos, arg := range args {
			argNode := &CallNodeArg{
				parent:   node,
				ssaValue: arg,
				out:      make(map[GraphNode]objectPath),
			}
			node.args[pos] = argNode
		}
		g.addCallNode(node)
	}

	if len(callees) == 0 {
		c.Logger.Printf("No callee found for %s.\n", instr.String())
		c.Logger.Printf("Location: %s.\n", instr.Parent().Prog.Fset.Position(instr.Pos()))
		if instr.Value() != nil {
			fmt.Printf("Value: %s\n", instr.Value().String())
			fmt.Printf("Type: %s\n", instr.Value().Type())
		} else {
			fmt.Printf("Type: %s\n", instr.Common().Value.Type())
		}

		fmt.Printf("Method: %s\n", instr.Common().Method)
		// TODO: remove that when we have a method to resolve all callees
		node := &CallNode{
			parent:   g,
			callee:   nil,
			args:     make([]*CallNodeArg, len(args)),
			callSite: instr,
			out:      make(map[GraphNode]objectPath),
		}

		for pos, arg := range args {
			argNode := &CallNodeArg{
				parent:   node,
				ssaValue: arg,
				out:      make(map[GraphNode]objectPath),
			}
			node.args[pos] = argNode
		}
		g.addCallNode(node)
	}
}

// addReturn adds a return node to the summary
// @requires g != nil
func (g *SummaryGraph) addReturn(instr ssa.Instruction, node *ReturnNode) {
	if _, ok := g.returns[instr]; !ok {
		g.returns[instr] = node
	}
}

// Functions to add edges to the graph

// addEdge adds an edge between source and dest in the summary graph g.
// @requires g != nil
func (g *SummaryGraph) addEdge(source Source, dest GraphNode) {
	// This function's goal is to define how the source of an edge is obtained in the summary given a Source that
	// is produced in the intra-procedural analysis.
	if source.IsParameter() {
		if sourceArgNode, ok := g.params[source.Node]; ok && sourceArgNode != dest {
			sourceArgNode.out[dest] = source.RegionPath
		}
	}

	if source.IsCallSiteArg() {
		// A CallSite source node must be a CallInstruction
		sourceCallInstr := source.Node.(ssa.CallInstruction)
		// and it must have a qualifier representing the argument
		if sourceNodes, ok := g.callees[sourceCallInstr]; ok {
			for _, sourceNode := range sourceNodes {
				sourceCallArgNode := sourceNode.FindArg(source.Qualifier)
				if sourceCallArgNode != nil && sourceCallArgNode != dest {
					sourceCallArgNode.out[dest] = source.RegionPath
				}
			}
		}
	}

	if source.IsCallReturn() {
		// A CallReturn source node must be a CallInstruction
		sourceCallInstr := source.Node.(ssa.CallInstruction)
		if sourceNodes, ok := g.callees[sourceCallInstr]; ok {
			for _, sourceNode := range sourceNodes {
				if sourceNode != dest {
					sourceNode.out[dest] = source.RegionPath
				}
			}

		}
	}
}

// addCallArgEdge adds an edge in the summary from a source to a function call argument
// @requires g != nil
func (g *SummaryGraph) addCallArgEdge(source Source, call ssa.CallInstruction, arg ssa.Value) {
	callNodes := g.callees[call]
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
		g.addEdge(source, callNodeArg)
	}
}

// addReturnEdge adds an edge in the summary from the source to a return instruction
// @requires g != nil
func (g *SummaryGraph) addReturnEdge(source Source, retInstr ssa.Instruction) {
	retNode := g.returns[retInstr]

	if retNode == nil {
		g.addError(fmt.Errorf("attempting to set return edge but no return node"))
		return
	}

	g.addEdge(source, retNode)
}

// addParamEdge adds an edge in the summary from the source to a parameter of the function
func (g *SummaryGraph) addParamEdge(source Source, param ssa.Node) {
	paramNode := g.params[param]

	if paramNode == nil {
		g.addError(fmt.Errorf("attempting to set param edge but no param node"))
	}

	g.addEdge(source, paramNode)
}

// Loading function summaries from predefined summaries

// addParamEdgeByPos adds an edge between the arguments at position src and dest in the summary graph.
// Returns true if it successfully added an edge.
// Returns false if it failed to add an edge because it could not fetch the required data (the positions might not be
// correct)
func (g *SummaryGraph) addParamEdgeByPos(src int, dest int) bool {
	n := len(g.parent.Params)
	if src < 0 || src >= n || dest < 0 || dest >= n {
		return false
	}
	srcNode := g.parent.Params[src]
	destNode := g.parent.Params[dest]

	if srcNode == nil || destNode == nil {
		return false
	}

	if srcArg, ok := g.params[srcNode]; ok {
		if destArg, ok := g.params[destNode]; ok {
			srcArg.out[destArg] = ""
			return true
		}
	}
	return false
}

// addReturnEdgeByPos adds an edge between the parameter at position src to the returned tuple position dest.
// The tuple position is simply ignored.
// TODO: change this when we support tracking tuple indexes.
func (g *SummaryGraph) addReturnEdgeByPos(src int, _ int) bool {
	if src < 0 || src >= len(g.parent.Params) {
		return false
	}
	srcNode := g.parent.Params[src]
	if srcNode == nil {
		return false
	}

	if srcArg, ok := g.params[srcNode]; ok {
		// Add edge to any return
		for _, retNode := range g.returns {
			srcArg.out[retNode] = ""
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
func LoadPredefinedSummary(f *ssa.Function, cg *callgraph.Graph) *SummaryGraph {
	preDef, ok := summaries.SummaryOfFunc(f)
	if !ok {
		return nil
	}
	summaryBase := NewSummaryGraph(f, cg.Nodes[f])
	// Add edges from parameter to parameter
	for srcArg, destArgs := range preDef.TaintingArgs {
		for _, destArg := range destArgs {
			summaryBase.addParamEdgeByPos(srcArg, destArg)
		}
	}
	// Add edges from parameter to return instruction
	for srcArg, retArray := range preDef.TaintingRets {
		for _, retIndex := range retArray {
			summaryBase.addReturnEdgeByPos(srcArg, retIndex)
		}
	}
	// Clean callees for a predefined summary
	summaryBase.callees = map[ssa.CallInstruction][]*CallNode{}
	// A summary graph loaded from a predefined summary is marked as constructed.
	summaryBase.constructed = true
	return summaryBase
}

// Utilities for printing graphs

func (a *ParamNode) String() string {
	return "\"" + a.ssaNode.String() + "\""
}

func (a *CallNodeArg) String() string {
	return fmt.Sprintf("\"call:%s, arg:%s\"", a.parent.callSite.String(), a.ssaValue.Name())
}

func (a *CallNode) String() string {
	return fmt.Sprintf("\"call: %s\"", a.callSite.String())
}

func (a *ReturnNode) String() string {
	return fmt.Sprintf("\"%s.return\"", a.parent.parent.Name())
}

// print the summary graph to w in the graphviz format.
// If g is nil, then prints the empty graph "subgraph {}"
func (g *SummaryGraph) print(w io.Writer) {
	if g == nil || g.parent == nil {
		fmt.Fprintf(w, "subgraph {}\n")
		return
	}
	fmt.Fprintf(w, "subgraph %s {\n", g.parent.Name())
	for _, a := range g.params {
		for n := range a.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", a.String(), n.String())
		}
	}
	for _, callNodes := range g.callees {
		for _, callN := range callNodes {
			for n := range callN.Out() {
				fmt.Fprintf(w, "\t%s -> %s;\n", callN.String(), n.String())
			}
			for _, x := range callN.args {
				for n := range x.Out() {
					fmt.Fprintf(w, "\t%s -> %s;\n", x.String(), n.String())
				}
			}
		}
	}
	for _, r := range g.returns {
		for n := range r.Out() {
			fmt.Fprintf(w, "\t%s -> %s;\n", r.String(), n.String())
		}
	}
	fmt.Fprint(w, "}\n")
}
