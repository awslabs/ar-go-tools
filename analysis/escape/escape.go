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

// The escape analysis computes a representation of which references in the program are to objects
// that are local to the current function and goroutine. This information can be used to recover
// local reasoning even in the face of concurrent goroutine evolution. This implementation is inspired
// by:
//   John Whaley and Martin Rinard. 1999. Compositional pointer and escape analysis for Java programs.
//   SIGPLAN Not. 34, 10 (Oct. 1999), 187–206. https://doi.org/10.1145/320385.320400
package escape

import (
	"bytes"
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"sort"

	"github.com/awslabs/argot/analysis/astfuncs"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// Effectively an enum of the types of node.
type NodeKind int

const (
	KindAlloc    NodeKind = iota // Cells of allocations that happen locally
	KindParam                    // Pointees of initial pointer-like parameters
	KindLoad                     // Represent the object loaded from a pointer/field of an external object
	KindGlobal                   // The memory location of a heap object
	KindVar                      // A local variable, i.e. SSA var
	KindParamVar                 // A parameter variable (both formals and free variables/method receiver)
	KindReturn                   // The return value of the current function
)

// A node represents the objects tracked by the escape analysis.
// Nodes represent local variables, globals, parameters, and heap
// cells of various kinds (maps, slices, arrays, structs)
type Node struct {
	kind      NodeKind
	number    int    // For unambigous debug printing
	debugInfo string // where this node comes from
}

func (n *Node) String() string {
	return fmt.Sprintf("%d<%s>", n.number, n.debugInfo)
}

// Certain nodes are intrinsically external: parameters, loads, and globals.
// Note that this doesn't include ParamVars, which are the (local) pointers
// at the external objects.
func (n *Node) IsIntrinsicallyExternal() bool {
	switch n.kind {
	case KindParam, KindLoad, KindGlobal:
		return true
	}
	return false
}

// The escape graph is the element of the monotone framework and the primary
// focus of the escape analysis. The graph represents edges as src -> dest
// -> isInternal. The final bool is semantically significant: the edges are
// labeled as internal or external. Escaped is a set of nodes that are not
// known to be local in the current context; they are treated differently on
// load operations. The major operations on escape graphs are to AddEdge()s,
// (plus composite operations like Load, WeakAssign), Merge(), and compare
// with Matches().
type EscapeGraph struct {
	edges   map[*Node]map[*Node]bool
	escaped map[*Node]bool
}

// Produces an empty graph, which is also the unit of Merge() below
func NewEmptyEscapeGraph() *EscapeGraph {
	gg := &EscapeGraph{
		make(map[*Node]map[*Node]bool),
		make(map[*Node]bool),
	}
	return gg
}

// Clones a graph, but preserves node identities between the two graphs.
func (g *EscapeGraph) Clone() *EscapeGraph {
	gg := NewEmptyEscapeGraph()
	for k, v := range g.edges {
		m := make(map[*Node]bool, len(v))
		for k2, v2 := range v {
			m[k2] = v2
		}
		gg.edges[k] = m
	}
	for k, v := range g.escaped {
		gg.escaped[k] = v
	}
	return gg
}

// Return a (multi-line) string representation suitable for debug printing.
// Not very visual, but easier to read in a terminal. See also Graphviz() below.
func (g *EscapeGraph) Debug(nodes *NodeGroup) string {
	out := bytes.NewBuffer([]byte{})

	ordered := []*Node{}
	for _, o := range nodes.variables {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.allocs {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.globals {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.params {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.loads {
		ordered = append(ordered, o)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].number < ordered[j].number })

	for _, v := range ordered {
		fmt.Fprintf(out, "%v -> ", v.number)
		first := true
		for n := range g.edges[v] {
			if !first {
				fmt.Fprintf(out, ", ")
			}
			first = false
			fmt.Fprintf(out, "%d", n.number)
		}
		escapedString := ""
		if g.escaped[v] {
			escapedString = ", *Escaped"
		}
		fmt.Fprintf(out, "    <%v>%s\n", v.debugInfo, escapedString)
	}

	return out.String()
}

// Return a (multi-line) dot/graphviz input describing the graph.
func (g *EscapeGraph) Graphviz(nodes *NodeGroup) string {
	return g.GraphvizLabel(nodes, "")
}

// Adds a label to the graph; useful for e.g. the function being analyzed
func (g *EscapeGraph) GraphvizLabel(nodes *NodeGroup, label string) string {
	out := bytes.NewBuffer([]byte{})
	fmt.Fprintf(out, "digraph { // start of digraph\nrankdir = LR;\n")
	fmt.Fprintf(out, "graph[label=\"%s\"];\n", label)

	ordered := []*Node{}
	for _, o := range nodes.variables {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.allocs {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.globals {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.params {
		ordered = append(ordered, o)
	}
	for _, o := range nodes.loads {
		ordered = append(ordered, o)
	}
	if nodes.returnNode != nil {
		ordered = append(ordered, nodes.returnNode)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].number < ordered[j].number })

	fmt.Fprintf(out, "subgraph {\nrank=same;\n")
	prevInVarBlock := -1
	for _, v := range ordered {
		if v.kind == KindVar || v.kind == KindParamVar || v.kind == KindReturn {
			extra := "shape=rect style=rounded width=0 height=0 margin=0.05 "
			if g.escaped[v] {
				extra += " style=\"dashed,rounded\""
			}
			fmt.Fprintf(out, "%d [label=\"%s\" %s];\n", v.number, v.debugInfo, extra)
			if prevInVarBlock >= 0 {
				fmt.Fprintf(out, "%d -> %d [style=invis];\n", prevInVarBlock, v.number)
			}
			prevInVarBlock = v.number
		}
	}
	fmt.Fprintf(out, "} // subgraph\n")
	for _, v := range ordered {
		if !(v.kind == KindVar || v.kind == KindParamVar || v.kind == KindReturn) {
			extra := "shape=rect"
			if g.escaped[v] {
				extra += " style=dashed"
			}
			fmt.Fprintf(out, "%d [label=\"%s\" %s];\n", v.number, v.debugInfo, extra)
		}
		for n, isInternal := range g.edges[v] {
			extra := ""
			if !isInternal {
				extra = "style=dashed"
			}
			fmt.Fprintf(out, "%d -> %d [%s];\n", v.number, n.number, extra)
		}
	}

	fmt.Fprintf(out, "} // end of digraph\n")
	return out.String()
}

// Adds an edge from base to dest. isInternal (almost always `true`) signals whether
// this is an internal edge (created during the current function) or external edge
// (possibly existed before the current function).
func (g *EscapeGraph) AddEdge(base *Node, dest *Node, isInternal bool) {
	g.addEdgeNoClosure(base, dest, isInternal)
	g.ComputeTransitiveClosure()
}

// Ensures g has an entry for n.
// This is necessary to ensure that EscapeClosure() knows about n, as it
// does not have access to the relevant NodeGroup.
func (g *EscapeGraph) AddNode(n *Node) {
	if _, ok := g.edges[n]; !ok {
		g.edges[n] = map[*Node]bool{}
	}
}

// The same as adding an edge, but without recomputing the closure of escape.
// Useful when you are adding a bunch of edges to avoid the cost of recomputing
// closure each time, and then doing it once at the end.
func (g *EscapeGraph) addEdgeNoClosure(base *Node, dest *Node, isInternal bool) {
	// Make sure the destination is a node, so when we iterate over all nodes it will be enumerated.
	g.AddNode(dest)
	if _, ok := g.edges[base]; ok {
		// If the existing edge is already internal (map value is true), don't change it.
		// If the existing edge is external, and we are adding an internal edge, upgrade it.
		// Otherwise, we'll add the external edge (false value) to the map
		g.edges[base][dest] = isInternal || g.edges[base][dest]
	} else {
		g.edges[base] = map[*Node]bool{dest: isInternal}
	}
}

// Applies the weak-assignment operation `dest = src`. Basically, ensures that
// dest points to whatever src points to. Weak here means that it does not erase
// any existing edges from dest
func (g *EscapeGraph) WeakAssign(dest *Node, src *Node, t types.Type) {
	edgePointees := g.Deref(src)
	for e := range edgePointees {
		g.addEdgeNoClosure(dest, e, true)
	}
	g.ComputeTransitiveClosure()
}

// Applies the load operation `valNode = *addrNode`. This is a generalized operation:
// it also applies to reading from slices, maps, globals, etc.
// generateLoadNode is called if the load can happen against an external object; this
// can't be determined a priori, and we don't want to create a load node unless necessary
func (g *EscapeGraph) Load(valNode *Node, addrNode *Node, generateLoadNode func() *Node) {
	var loadNode *Node
	// Nodes are addr ->* addrPointee ->* doublePointee
	// val = *addr means we need to add edges from val to whatever node(s) *addr points to
	// The addrPointees are the nodes that addr points to, and the doublePointees are collectively
	// everything that *addr points to. Thus we need to collect all double pointees and add edges
	// from val to these.
	for addrPointee := range g.Deref(addrNode) {
		g.AddNode(addrPointee)
		for doublePointee := range g.edges[addrPointee] { // TODO: should this also be .Deref(addrPointee)?
			g.addEdgeNoClosure(valNode, doublePointee, true)
		}
		// if addrPointee is an escaped node, we need to add the load node
		if g.escaped[addrPointee] {
			if loadNode == nil {
				loadNode = generateLoadNode()
			}
			g.addEdgeNoClosure(valNode, loadNode, true)
			g.addEdgeNoClosure(addrPointee, loadNode, false)
		}
	}
	// TODO: for load operations, if the pointer node itself (not just its pointee) is external then we have a
	// problem, as it will also need a load node. This may not occur depending on how the SSA is constructed, i.e.
	// if we only have e.g. instrType.X represented by a local variable (which will never be external).
	g.ComputeTransitiveClosure()
}

// Computes the reachability-based closure of escape over the edges of the graph.
// The roots are the nodes that are .IsIntrinsicallyExternal(). Then, if A has
// escaped, and there's an edge from A to B, then B has escaped too.
func (g *EscapeGraph) ComputeTransitiveClosure() {
	worklist := []*Node{}
	for node, edges := range g.edges {
		if node.IsIntrinsicallyExternal() && !g.escaped[node] {
			g.escaped[node] = true
			worklist = append(worklist, node)
		}
		if g.escaped[node] {
			for e := range edges {
				if !g.escaped[e] {
					g.escaped[e] = true
					worklist = append(worklist, e)
				}
			}
		}
	}
	for len(worklist) > 0 {
		node := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		for succ := range g.edges[node] {
			if !g.escaped[succ] {
				g.escaped[succ] = true
				worklist = append(worklist, succ)
			}
		}
	}
}

// Computes the union of this graph with another, used at the join-points of a dataflow graph.
func (g *EscapeGraph) Merge(h *EscapeGraph) {
	for node, edges := range h.edges {
		g.AddNode(node)
		for dest, isInternal := range edges {
			g.AddEdge(node, dest, isInternal)
		}
	}
	g.ComputeTransitiveClosure()
}

// Checks if two graphs are equal. Used for convergence checking.
func (g *EscapeGraph) Matches(h *EscapeGraph) bool {
	// TODO: This may become a performance bottleneck
	return reflect.DeepEqual(g.edges, h.edges) && reflect.DeepEqual(g.escaped, h.escaped)
}

// A node group stores the identity of nodes within a current function context, and ensures
// that e.g. a single load node is shared between all invocations of a load instruction, or
// all allocations in a particular function.
type NodeGroup struct {
	variables  map[ssa.Value]*Node
	allocs     map[ssa.Instruction]*Node
	loads      map[ssa.Instruction]*Node
	globals    map[ssa.Value]*Node
	params     map[ssa.Value]*Node
	returnNode *Node
	nextNode   int // The next debug number to use for new nodes
}

func NewNodeGroup() *NodeGroup {
	return &NodeGroup{
		make(map[ssa.Value]*Node),
		make(map[ssa.Instruction]*Node),
		make(map[ssa.Instruction]*Node),
		make(map[ssa.Value]*Node),
		make(map[ssa.Value]*Node),
		nil,
		0,
	}
}

// Creates a node that represents an allocation, such as &S{}, make([]int, 3),
// map[int]int{}, etc.
func (g *NodeGroup) AllocNode(instr ssa.Instruction, t types.Type) *Node {
	node, ok := g.allocs[instr]
	if ok {
		return node
	}
	var qualifier types.Qualifier
	if instr.Parent().Package() != nil {
		qualifier = types.RelativeTo(instr.Parent().Package().Pkg)
	}
	shortTypeName := types.TypeString(t, qualifier)
	node = &Node{KindAlloc, g.nextNode, fmt.Sprintf("new %s L:%d", shortTypeName, instr.Parent().Prog.Fset.Position(instr.Pos()).Line)}
	g.nextNode += 1
	g.allocs[instr] = node
	return node
}

// Creates a node that represents a ssa.Value. Most such values are virtual registers created
// by instructions, e.g. the t1 in `t1 = *t0`.
func (g *NodeGroup) ValueNode(variable ssa.Value) *Node {
	// a ssa.Value is one of:
	// - Parameter, Builtin, Function, FreeVar, Global
	// - Constant
	// - an SSA variable in the traditional sense
	// Of these, SSA variables (ssa.Instruction), Parameters, FreeVar, and Globals have nodes.
	// Builtins, Functions, and Constants should not be passed to this function
	if _, ok := variable.(*ssa.Builtin); ok {
		panic("Not expecting built-in")
	}
	if c, ok := variable.(*ssa.Const); ok {
		if c.IsNil() {
			return nil
		}
	}

	node, ok := g.variables[variable]
	if ok {
		return node
	}
	kind := KindVar
	kindStr := ""
	if _, ok := variable.(*ssa.Global); ok {
		kind = KindGlobal
		kindStr = "gbl:"
	} else if _, ok := variable.(*ssa.Parameter); ok {
		kind = KindParamVar
		kindStr = "param:"
	} else if _, ok := variable.(*ssa.FreeVar); ok {
		kind = KindParamVar
		kindStr = "free:"
	}
	node = &Node{kind, g.nextNode, kindStr + variable.Name()}
	g.nextNode += 1
	g.variables[variable] = node
	return node
}

// The return node of a function, which represents the implicit or explicit variables
// that capture the returned values. There is one node per function.
func (g *NodeGroup) ReturnNode() *Node {
	if g.returnNode != nil {
		return g.returnNode
	}
	node := &Node{KindReturn, g.nextNode, "return"}
	g.nextNode += 1
	g.returnNode = node
	return node
}

// Creates a load node, which represents the object(s) that are potentially
// reached through some load-like operation, e.g. *ptr, map[key], etc.
func (g *NodeGroup) LoadNode(instr ssa.Instruction, t types.Type) *Node {
	node, ok := g.loads[instr]
	if ok {
		return node
	}
	var qualifier types.Qualifier
	if instr.Parent().Package() != nil {
		qualifier = types.RelativeTo(instr.Parent().Package().Pkg)
	}
	shortTypeName := types.TypeString(t, qualifier)
	node = &Node{KindLoad, g.nextNode, fmt.Sprintf("%s load L:%d", shortTypeName, instr.Parent().Prog.Fset.Position(instr.Pos()).Line)}
	g.nextNode += 1
	g.loads[instr] = node
	return node
}

// Creates a node for the initial pointee of a parameter/freevar. This is different from the var node of the pointer,
// which exists for consistency with SSA values
func (g *NodeGroup) ParamNode(param ssa.Value) *Node {
	node, ok := g.params[param]
	if ok {
		return node
	}
	node = &Node{KindParam, g.nextNode, "pointee of " + param.Name()}
	g.nextNode += 1
	g.params[param] = node
	return node
}

// This function is required because globals are not represented in a uniform way with
// parameters/locals/freevars. In the SSA form, a global is implicitly a pointer to the
// its type. So if we have a global decl:
//     var global *S
// then in the SSA, the global name effectively has type **S. We can see this in that the
// operation global = &S{} turns into `t0 = alloc S; *global = t0`. The current graph
// representation makes the global node directly the node that stores the value, rather
// than pointing at a virtual node that then points at the actual value like a **S parameter
// would. This decision was made so that globals could be instantiated lazily via the
// NodeGroup: they don't need to create two nodes with an edge like params/freevars do.
// This is probably the wrong choice; instead, these node pairs should be created based
// on a scan of the instructions for globals that are accessed, during the creation
// of the initial escape graph.
func (g *EscapeGraph) Deref(addr *Node) map[*Node]bool {
	if addr == nil {
		return map[*Node]bool{}
	}
	addrPointees := g.edges[addr]
	if addr.kind == KindGlobal {
		addrPointees = map[*Node]bool{addr: true}
	}
	return addrPointees
}

// Derefs specifically pointer types (or their aliases). No-op otherwise
func PointerDerefType(t types.Type) types.Type {
	switch tt := t.(type) {
	case *types.Pointer:
		return tt.Elem()
	case *types.Named:
		return PointerDerefType(tt.Underlying())
	default:
		return tt
	}
}

// The primary transfer function for an instruction's effect on a escape graph.
// Modifies g and nodes in place with the effects of the instruction.
func transferFunction(instr ssa.Instruction, g *EscapeGraph, nodes *NodeGroup) {
	// Switch on the instruction to handle each kind of instructions.
	// Some instructions have sub-kinds depending on their arguments, or have alternate comma-ok forms.
	// If an instruction is handled, return. Otherwise, fall through to the end of the function to print
	// a warning about an unhandled instruction. When the set of instructions is complete, this should turn
	// into an error/panic.
	switch instrType := instr.(type) {
	case *ssa.Alloc:
		g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, PointerDerefType(instrType.Type())), true)
		return
	case *ssa.MakeClosure:
		closureNode := nodes.AllocNode(instrType, instrType.Type())
		g.AddEdge(nodes.ValueNode(instrType), closureNode, true)
		for _, bindingVal := range instrType.Bindings {
			g.WeakAssign(closureNode, nodes.ValueNode(bindingVal), bindingVal.Type())
		}
		return
	case *ssa.MakeMap:
		g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, instrType.Type()), true)
		return
	case *ssa.MakeSlice:
		g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, instrType.Type()), true)
		return
	case *ssa.FieldAddr:
		for varPointee := range g.Deref(nodes.ValueNode(instrType.X)) {
			g.AddEdge(nodes.ValueNode(instrType), varPointee, true)
		}
		return
	case *ssa.IndexAddr:
		// TODO: array is different than *array and slice, as we need to know the object the array is part of
		for varPointee := range g.Deref(nodes.ValueNode(instrType.X)) {
			g.AddEdge(nodes.ValueNode(instrType), varPointee, true)
		}
		return
	case *ssa.Store:
		if astfuncs.IsNillableType(instrType.Val.Type()) {
			valNode := nodes.ValueNode(instrType.Val)
			addrNode := nodes.ValueNode(instrType.Addr)
			addrPointees := g.Deref(addrNode)
			valPointees := g.Deref(valNode)
			for addrPointee := range addrPointees {
				g.AddNode(addrPointee) // ensures that stores of nil still add the node to g
				// (the following loop has not iterations in this case)
				for valPointee := range valPointees {
					g.AddEdge(addrPointee, valPointee, true)
				}
			}
		}
		return
	case *ssa.UnOp:
		// Check if this is a load operation
		if _, ok := instrType.X.Type().(*types.Pointer); ok && instrType.Op == token.MUL {
			if astfuncs.IsNillableType(instrType.Type()) {
				gen := func() *Node {
					return nodes.LoadNode(instr, PointerDerefType(PointerDerefType(instrType.X.Type().Underlying())))
				}
				g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
			}
			return
		} else if _, ok := instrType.X.Type().(*types.Chan); ok && instrType.Op == token.ARROW {
			// recv on channel
			// TODO: implement this; for now fallthrough to the end of the switch statement
		} else {
			// arithmetic UnOp
			return
		}
	case *ssa.Slice:
		switch tp := instrType.X.Type().Underlying().(type) {
		case *types.Slice:
			// Slice of slice, basic copy
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
			return
		case *types.Basic:
			if tp.Kind() != types.String && tp.Kind() != types.UntypedString {
				panic("Slice of BasicKind that isn't string?" + tp.String())
			}
			// TODO: slice of a string should be treated as an allocation??
			// return g.WeakAssign(nodes.ValueNode(instrType), nodes.StringNode(), instrType.Type())
			return
		case *types.Pointer:
			if _, ok := tp.Elem().Underlying().(*types.Array); !ok {
				panic("Slice of pointer to non-array?")
			}
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
			return
		}
	case *ssa.Return:
		return
	case *ssa.Jump:
		return
	case *ssa.If:
		return
	// case *ssa.Call:
	// 	// print("Warning, skipping calls for now\n")
	// return g

	case *ssa.Defer:
	case *ssa.Field:
		if astfuncs.IsNillableType(instrType.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
		}
		return
	case *ssa.Index:
		switch tp := instrType.X.Type().Underlying().(type) {
		case *types.Basic:
			if tp.Kind() == types.String || tp.Kind() == types.UntypedString {
				// string index is no-op
				return
			}
		case *types.Slice:
			gen := func() *Node { return nodes.LoadNode(instr, PointerDerefType(PointerDerefType(instrType.X.Type()))) }
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
			return
		}
	case *ssa.Lookup:
		if astfuncs.IsNillableType(instrType.Type().Underlying()) {
			gen := func() *Node { return nodes.LoadNode(instr, instrType.Type()) }
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
		}
		return
	case *ssa.MapUpdate:
		// TODO: refactor this into a generic store like .Load and .WeakAssign
		if astfuncs.IsNillableType(instrType.Value.Type()) {
			valNode := nodes.ValueNode(instrType.Value)
			addrNode := nodes.ValueNode(instrType.Map)
			addrPointees := g.Deref(addrNode)
			valPointees := g.Deref(valNode)
			for addrPointee := range addrPointees {
				for valPointee := range valPointees {
					g.AddEdge(addrPointee, valPointee, true)
				}
			}
		}
		if astfuncs.IsNillableType(instrType.Key.Type()) {
			valNode := nodes.ValueNode(instrType.Key)
			addrNode := nodes.ValueNode(instrType.Map)
			addrPointees := g.Deref(addrNode)
			valPointees := g.Deref(valNode)
			for addrPointee := range addrPointees {
				for valPointee := range valPointees {
					g.AddEdge(addrPointee, valPointee, true)
				}
			}
		}
		return
	case *ssa.Next:
		if !instrType.IsString {
			gen := func() *Node { return nodes.LoadNode(instr, PointerDerefType(PointerDerefType(instrType.Iter.Type()))) }
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.Iter), gen)
		}
		return
	case *ssa.Range:
		if tp, ok := instrType.X.Type().Underlying().(*types.Map); ok {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), tp)
		} else {
			// range over string, not interesting to escape
			return
		}
		return
	case *ssa.MakeInterface:
		g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.X.Type())
		return
	case *ssa.TypeAssert:
		if astfuncs.IsNillableType(instrType.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
		}
		return
	case *ssa.Convert:
		if astfuncs.IsNillableType(instrType.Type()) {
			// TODO: conversion between string and []byte or []rune should be treated as an allocation
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
		}
		return
	case *ssa.ChangeInterface:
		g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.X.Type())
		return
	case *ssa.ChangeType:
		if astfuncs.IsNillableType(instrType.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.X.Type())
		}
		return
	case *ssa.Phi:
		if astfuncs.IsNillableType(instrType.Type()) {
			for _, v := range instrType.Edges {
				g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(v), instrType.Type())
			}
		}
		return
	case *ssa.Extract:
		if _, ok := instrType.Tuple.(*ssa.Phi); ok {
			panic("Extract from phi?")
		}
		if astfuncs.IsNillableType(instrType.Type()) {
			// Note: this is not tuple-sensitive. Because the SSA does not appear to separate the extract
			// op from the instruction that generates the tuple, we could save the precise information about
			// tuples on the side and lookup the correct node(s) here as opposed to collapsing into a single
			// node for the entire tuple.
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.Tuple), instrType.Type())
		}
		return
	case *ssa.BinOp:
		return
	default:
	}
	// fmt.Printf("Unhandled: (type: %s) %v\n", reflect.TypeOf(instr).String(), instr)
}

type escapeAnalysis struct {
	initialGraph *EscapeGraph
	nodes        *NodeGroup
	blockEnd     map[*ssa.BasicBlock]*EscapeGraph
}

func (ea *escapeAnalysis) ProcessBlock(bb *ssa.BasicBlock) bool {
	g := ea.initialGraph
	// If we have predecessors, we aren't the entry block
	if len(bb.Preds) > 0 {
		// The following code just makes a merged copy of all the block ends of the predecessor blocks
		// It is complicated by the fact that we need to ensure we Clone a new graph to modify in place,
		// and some of the predecessors can be nil.
		g = ea.blockEnd[bb.Preds[0]]
		if g != nil {
			g = g.Clone()
		}
		for _, pred := range bb.Preds[1:] {
			predGraph := ea.blockEnd[pred]
			if g == nil && predGraph != nil {
				g = predGraph.Clone()
			} else if predGraph != nil {
				g.Merge(predGraph)
			} // otherwise, both g and predGraph are nil
		}
	}
	if g == nil {
		// This panic should not fire as this block should only be processed
		// after a predecessor updates its result
		panic("At least one predecessor should have a non-nil end graph")
	}
	for _, instr := range bb.Instrs {
		transferFunction(instr, g, ea.nodes)
	}
	if oldGraph, ok := ea.blockEnd[bb]; ok {
		if oldGraph.Matches(g) {
			return false
		}
	}
	ea.blockEnd[bb] = g
	return true
}

// An implementation of the convergence loop of the monotonic framework.
// Each block is processed, and if it's result changes the successors are added.
func (e *escapeAnalysis) RunForwardIterative(function *ssa.Function) {
	if len(function.Blocks) == 0 {
		return
	}
	var worklist []*ssa.BasicBlock
	worklist = append(worklist, function.Blocks[0])
	for len(worklist) > 0 {
		block := worklist[0]
		worklist = worklist[1:]
		if e.ProcessBlock(block) {
			for _, nextBlock := range block.Succs {
				found := false
				for _, entry := range worklist {
					if entry == nextBlock {
						found = true
					}
				}
				if !found {
					worklist = append(worklist, nextBlock)
				}
			}
		}
	}
}

// Compute the escape summary for a single function.
// Currently this is independent of all other functions but this will need to change
// for the intraprocedural analysis, as e.g. recursive functions will require analyzing
// multiple functions concurrently.
func EscapeSummary(f *ssa.Function) (nodes *NodeGroup, graph *EscapeGraph) {
	nodes = NewNodeGroup()
	initialGraph := NewEmptyEscapeGraph()
	for _, p := range f.Params {
		initialGraph.AddEdge(nodes.ValueNode(p), nodes.ParamNode(p), true)
	}
	analysis := &escapeAnalysis{
		initialGraph,
		nodes,
		make(map[*ssa.BasicBlock]*EscapeGraph),
	}
	analysis.RunForwardIterative(f)
	returnResult := NewEmptyEscapeGraph()
	returnNode := nodes.ReturnNode()
	for block, blockEndState := range analysis.blockEnd {
		if len(block.Instrs) > 0 {
			if retInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return); ok {
				returnResult.Merge(blockEndState)
				for _, rValue := range retInstr.Results {
					if astfuncs.IsNillableType(rValue.Type()) {
						returnResult.WeakAssign(returnNode, nodes.ValueNode(rValue), rValue.Type())
					}
				}
			}
		}
	}
	returnResult.ComputeTransitiveClosure()
	return nodes, returnResult
}

// This just prints the escape summary for each function in the callgraph.
// This interface will change substaintially when intraprocedural analysis is finalized.
func EscapeAnalysis(root *callgraph.Node, ptrs *pointer.Result) error {
	for f := range ptrs.CallGraph.Nodes {
		nodes, graph := EscapeSummary(f)
		if f.Pkg != nil {
			if "main" == f.Pkg.Pkg.Name() {
				fmt.Printf("Func %s is:\n%s\n", f.String(), graph.GraphvizLabel(nodes, f.String()))
			}
		}
	}
	return nil
}
