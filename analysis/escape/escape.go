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

// Package escape provides an escape analysis which computes a representation of which references in the program are to objects
// that are local to the current function and goroutine. This information can be used to recover
// local reasoning even in the face of concurrent goroutine execution. This implementation is inspired
// by:
//
//	John Whaley and Martin Rinard. 1999. Compositional pointer and escape analysis for Java programs.
//	SIGPLAN Not. 34, 10 (Oct. 1999), 187–206. https://doi.org/10.1145/320385.320400
package escape

import (
	"bytes"
	"fmt"
	"go/token"
	"go/types"
	"log"
	"reflect"
	"sort"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/graphutil"
	"golang.org/x/tools/go/callgraph"
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
	KindUnknown                  // A return value from an unanalyzed method without a summary
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
	case KindParam, KindLoad, KindGlobal, KindUnknown:
		return true
	}
	return false
}
func (n *Node) IsIntrinsicallyLeaked() bool {
	switch n.kind {
	case KindGlobal, KindUnknown:
		return true
	}
	return false
}

// The escape graph is the element of the monotone framework and the primary
// focus of the escape analysis. The graph represents edges as src -> dest
// -> isInternal. The final bool is semantically significant: the edges are
// labeled as internal or external. Escaped is a set of nodes that are not
// known to be local in the current context; they are treated differently on
// load operations. Leaked is a subset of escaped nodes that have (possibly)
// leaked out of the current goroutine, whereas escaped nodes may still be
// local depending on the calling context. The major operations on escape
// graphs are to AddEdge()s, (plus composite operations like Load,
// WeakAssign), Merge(), and compare with Matches().
type EscapeGraph struct {
	edges   map[*Node]map[*Node]bool
	escaped map[*Node]bool
	leaked  map[*Node]bool
	nodes   *NodeGroup
}

// Produces an empty graph, which is also the unit of Merge() below
func NewEmptyEscapeGraph(nodes *NodeGroup) *EscapeGraph {
	gg := &EscapeGraph{
		make(map[*Node]map[*Node]bool),
		make(map[*Node]bool),
		make(map[*Node]bool),
		nodes,
	}
	return gg
}

// Clones a graph, but preserves node identities between the two graphs.
func (g *EscapeGraph) Clone() *EscapeGraph {
	gg := NewEmptyEscapeGraph(g.nodes)
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
	for k, v := range g.leaked {
		gg.leaked[k] = v
	}
	return gg
}

// Return a (multi-line) string representation suitable for debug printing.
// Not very visual, but easier to read in a terminal. See also Graphviz() below.
func (g *EscapeGraph) Debug() string {
	out := bytes.NewBuffer([]byte{})
	ordered := g.nodes.AllNodes()
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
		statusString := ""
		if g.escaped[v] {
			statusString = ", *Escaped"
		}
		if g.leaked[v] {
			statusString = ", *Leaked"
		}
		fmt.Fprintf(out, "    <%v>%s\n", v.debugInfo, statusString)
	}

	return out.String()
}

// Return a (multi-line) dot/graphviz input describing the graph.
func (g *EscapeGraph) Graphviz() string {
	return g.GraphvizLabel("")
}

// Adds a label to the graph; useful for e.g. the function being analyzed
func (g *EscapeGraph) GraphvizLabel(label string) string {
	out := bytes.NewBuffer([]byte{})
	fmt.Fprintf(out, "digraph { // start of digraph\nrankdir = LR;\n")
	fmt.Fprintf(out, "graph[label=\"%s\"];\n", label)
	fmt.Fprintf(out, "subgraph {\nrank=same;\n")
	prevInVarBlock := -1
	ordered := g.nodes.AllNodes()
	for _, v := range ordered {
		if v.kind == KindVar || v.kind == KindParamVar || v.kind == KindReturn {
			extra := "shape=rect style=rounded width=0 height=0 margin=0.05 "
			if g.escaped[v] {
				extra += " style=\"dashed,rounded\""
			}
			if g.leaked[v] {
				extra += " peripheries=2"
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
			if g.leaked[v] {
				extra += " peripheries=2"
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
func (g *EscapeGraph) AddEdge(base *Node, dest *Node, isInternal bool) (changed bool) {
	if !g.addEdgeNoClosure(base, dest, isInternal) {
		return false
	}
	g.computeTransitiveClosure()
	return true
}

// Ensures g has an entry for n.
// This is necessary to ensure that EscapeClosure() knows about n, as it
// does not have access to the relevant NodeGroup.
func (g *EscapeGraph) AddNode(n *Node) (changed bool) {
	if _, ok := g.edges[n]; !ok {
		g.edges[n] = map[*Node]bool{}
		return true
	}
	return false
}

// The same as adding an edge, but without recomputing the closure of escape.
// Useful when you are adding a bunch of edges to avoid the cost of recomputing
// closure each time, and then doing it once at the end. Returns whether the
// graph was changed by the operation.
func (g *EscapeGraph) addEdgeNoClosure(base *Node, dest *Node, isInternal bool) (changed bool) {
	// Make sure the destination is a node, so when we iterate over all nodes it will be enumerated.
	changedOnAddNode := g.AddNode(dest)
	if m, ok := g.edges[base]; ok {
		// If the existing edge is already internal (map value is true), don't change it.
		// If the existing edge is external, and we are adding an internal edge, upgrade it.
		// Otherwise, we'll add the external edge (false value) to the map
		if oldEdgeIsInternal, ok := m[dest]; ok {
			if oldEdgeIsInternal == (oldEdgeIsInternal || isInternal) {
				return changedOnAddNode
			}
			m[dest] = oldEdgeIsInternal || isInternal
			return true
		}
		// no edge of any kind between
		m[dest] = isInternal
		return true
	} else {
		g.edges[base] = map[*Node]bool{dest: isInternal}
		return true
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
	g.computeTransitiveClosure()
}

// Applies the load operation `valNode = *addrNode`. This is a generalized operation:
// it also applies to reading from slices, maps, globals, etc.
// generateLoadNode is called if the load can happen against an external object; this
// can't be determined a priori, and we don't want to create a load node unless necessary
func (g *EscapeGraph) Load(valNode *Node, addrNode *Node, generateLoadNode func() *Node) {
	var loadNode *Node
	// Nodes are addr ->* addrPointee ->* doublePointee
	// val = *addr means we need to add edges from val to whatever node(s) *addr (i.e. all the addrPointees)'
	// points to. The addrPointees are the nodes that addr points to, and the doublePointees are collectively
	// everything that *addr points to. Thus we need to collect all double pointees and add edges
	// from val to these nodes.
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
	g.computeTransitiveClosure()
}

// (Re)-computes the transitive closure of the leaked and escaped properties.
// This shouldn't be necessary to call manually unless you are using addEdgeNoClosure
func (g *EscapeGraph) computeTransitiveClosure() {
	// Compute leaked first, as escape depends on it
	g.computeTransitiveClosureForLeaked()
	g.computeTransitiveClosureForEscape()
}

// Computes the reachability-based closure of escape over the edges of the graph.
// The roots are the nodes that are .IsIntrinsicallyExternal() or leaked. Then, if
// A has escaped, and there's an edge from A to B, then B has escaped too.
func (g *EscapeGraph) computeTransitiveClosureForEscape() {
	worklist := []*Node{}
	for node := range g.edges {
		if node.IsIntrinsicallyExternal() || g.escaped[node] || g.leaked[node] {
			g.escaped[node] = true
			worklist = append(worklist, node)
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

// This is the same as computing closure for escaped, but for leaked. The difference
// is that in general fewer things will be leaked than escaped. Because leak implies
// escaped, this should be called before closure for escaped, so that it can propagate
// properly.
func (g *EscapeGraph) computeTransitiveClosureForLeaked() {
	worklist := []*Node{}
	for node := range g.edges {
		if node.IsIntrinsicallyLeaked() || g.leaked[node] {
			g.leaked[node] = true
			worklist = append(worklist, node)
		}
	}
	for len(worklist) > 0 {
		node := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		for succ := range g.edges[node] {
			if !g.leaked[succ] {
				g.leaked[succ] = true
				worklist = append(worklist, succ)
			}
		}
	}
}

// Computes the union of this graph with another, used at the join-points of a dataflow graph.
func (g *EscapeGraph) Merge(h *EscapeGraph) {
	for node, edges := range h.edges {
		g.AddNode(node)
		if h.leaked[node] {
			g.leaked[node] = true
		}
		for dest, isInternal := range edges {
			g.addEdgeNoClosure(node, dest, isInternal)
		}
	}
	g.computeTransitiveClosure()
}

// Computes the result of splicing in the summary (callee) of the callee's graph.
// args are the nodes corresponding to the caller's actual parameters at the callsite (nil if not pointer-like)
// rets are the nodes corresponding to the caller values to assign the results to (nil if not pointer-like)
// nodes is the NodeGroup for the caller, and also therefore the graph g
// summary is the summary of the called function.
// summaryNodes is the nodeGroup in the context of the called function
func (g *EscapeGraph) Call(args []*Node, rets []*Node, callee *EscapeGraph) {
	pre := g.Clone()
	// u maps nodes in summary to the nodes in the caller that
	u := map[*Node]map[*Node]struct{}{}
	addUEdge := func(x, y *Node) bool {
		if m, ok := u[x]; ok {
			if _, ok := m[y]; ok {
				return false
			}
			m[y] = struct{}{}
			return true
		}
		u[x] = map[*Node]struct{}{y: {}}
		return true
	}
	changed := false
	setChanged := func(b bool) {
		if b {
			changed = true
		}
	}
	if len(args) != len(callee.nodes.formals) {
		panic("Incorrect number of arguments")
	}
	for i, formal := range callee.nodes.formals {
		if (args[i] == nil) != (formal == nil) {
			panic("Incorrect nil-ness of corresponding parameter nodes")
		}
		addUEdge(formal, args[i])
	}
	for _, ret := range rets {
		if ret != nil {
			addUEdge(callee.nodes.ReturnNode(), ret)
		}
	}

	for {
		changed = false

		// propagate u edges for load nodes in the callee that are referenced internally in the caller
		// Creates the edge labeled u' in the following:
		// rep --------> v
		//  |            |
		//  | u          | u'
		//  |            |
		// base - - - > load
		//
		// Base cannot be an alloc node, as then the external load edge must have been created
		// after the allocation (e.g. if the base node was leaked)
		for base, repNodes := range u {
			// Alloc nodes did not exist when the call occurred, so these edges cannot point to a node in the original
			if base.kind == KindAlloc {
				continue
			}
			for load, isBaseLoadInternal := range callee.edges[base] {
				// Need base - - - > load to be an external edge (but also treat edges from param nodes as external)
				if isBaseLoadInternal && base.kind != KindParamVar {
					continue
				}
				for rep := range repNodes {
					for v, isRepVInternal := range pre.edges[rep] {
						if isRepVInternal {
							setChanged(addUEdge(load, v))
						}
					}
				}
			}
		}
		// propagate internal edges created in the callee
		// Creates a new edge rep --> x in the following:
		// rep          x
		//  |           |
		//  | u         | u
		//  |           |
		// base ------> y
		for base, repNodes := range u {
			for y, isBaseYInternal := range callee.edges[base] {
				// Need base -> y to be an internal edge (i.e. created during the execution of callee)
				if !isBaseYInternal {
					continue
				}
				for rep := range repNodes {
					for x := range u[y] {
						setChanged(g.AddEdge(rep, x, true))
					}
				}
			}
		}
		// propagate allocations/possible allocations (from un-analyzed functions)
		// Adds node alloc to g, and adds the mapping edge u'
		// rep          alloc
		//  |           |
		//  | u         | u'
		//  |           |
		// base ------> alloc
		// Rep is required to exist but we don't do anything with it. This makes sure
		// we only add the alloc node if it will be visible in the caller
		for base, repNodes := range u {
			if len(repNodes) == 0 {
				continue
			}
			for alloc, isBaseAllocInternal := range callee.edges[base] {
				if !isBaseAllocInternal || (alloc.kind != KindAlloc && alloc.kind != KindUnknown) {
					continue
				}
				setChanged(g.nodes.AddForeignNode(alloc))
				setChanged(g.AddNode(alloc))
				setChanged(addUEdge(alloc, alloc))
			}
		}
		// propagate load nodes that are referenced by escaped nodes
		// Adds node load to g, and adds the mapping edge u'
		// rep  - - -> load
		//  |           |
		//  | u         | u'
		//  |           |
		// base - - -> load
		// Rep is required to be escaped.
		for base, repNodes := range u {
			if len(repNodes) == 0 {
				continue
			}
			for rep := range repNodes {
				if !pre.escaped[rep] {
					continue
				}
				for load, isBaseLoadInternal := range callee.edges[base] {
					if isBaseLoadInternal {
						continue
					}
					setChanged(g.AddNode(load))
					setChanged(g.nodes.AddForeignNode(load))
					for rep := range repNodes {
						setChanged(g.AddEdge(rep, load, false))
					}
					setChanged(addUEdge(load, load))
				}
			}
		}
		// Propagating "escaped" information is tricky. We need to make a distinction between things
		// that could have escaped to the heap, and just things that are parameters/loads from the callee's
		// perspective. This means that we propagate "leaked" along u edges but not "escaped."
		for base, repNodes := range u {
			if callee.leaked[base] {
				for rep := range repNodes {
					if !g.leaked[rep] {
						changed = true
						g.leaked[rep] = true
						g.escaped[rep] = true
					}
				}
			}
		}

		// Check if no changes occured.
		if !changed {
			break
		}
	}
}

// Computes the result of calling an unknown function.
// An unknown function has no bound on its allow semantics. This means that the
// arguments are assumed to leak, and the return value is treated similarly to a
// load node, except it can never be resolved with arguments like loads can be.
func (g *EscapeGraph) CallUnknown(args []*Node, rets []*Node) {
	for _, arg := range args {
		for n := range g.edges[arg] {
			g.leaked[n] = true
		}
	}
	for _, ret := range rets {
		g.AddEdge(ret, g.nodes.UnknownReturnNode(), true)
	}
}

// Checks if two graphs are equal. Used for convergence checking.
func (g *EscapeGraph) Matches(h *EscapeGraph) bool {
	// TODO: This may become a performance bottleneck
	return reflect.DeepEqual(g.edges, h.edges) && reflect.DeepEqual(g.escaped, h.escaped) && reflect.DeepEqual(g.leaked, h.leaked)
}

type globalNodeGroup struct {
	nextNode int
	// TODO: introduce a mutex around nextNode for multithreading
}

// getNewID generates a new globally unique id for a node. The id is used to uniquely identify
// nodes without needing to rely on addresses (i.e. for debugging) and provides a way to sort
// nodes that is deterministic (as long as node creation is deterministic).
func (gn *globalNodeGroup) getNewID() int {
	i := gn.nextNode
	gn.nextNode += 1
	return i
}

// A node group stores the identity of nodes within a current function context, and ensures
// that e.g. a single load node is shared between all invocations of a load instruction, or
// all allocations in a particular function.
type NodeGroup struct {
	variables     map[ssa.Value]*Node
	allocs        map[ssa.Instruction]*Node
	loads         map[ssa.Instruction]*Node
	globals       map[ssa.Value]*Node
	foreign       map[*Node]struct{}
	params        map[ssa.Value]*Node
	formals       []*Node
	returnNode    *Node
	unknownReturn *Node
	globalNodes   *globalNodeGroup
}

func NewNodeGroup(globalNodes *globalNodeGroup) *NodeGroup {
	return &NodeGroup{
		make(map[ssa.Value]*Node),
		make(map[ssa.Instruction]*Node),
		make(map[ssa.Instruction]*Node),
		make(map[ssa.Value]*Node),
		make(map[*Node]struct{}),
		make(map[ssa.Value]*Node),
		make([]*Node, 0),
		nil,
		nil,
		globalNodes,
	}
}

// Returns all nodes in the group, sorted by their number.
func (nodes *NodeGroup) AllNodes() []*Node {
	ordered := []*Node{}
	alreadyAdded := map[*Node]bool{}
	add := func(o *Node) {
		if !alreadyAdded[o] {
			alreadyAdded[o] = true
			ordered = append(ordered, o)
		}
	}
	for _, o := range nodes.variables {
		add(o)
	}
	for _, o := range nodes.allocs {
		add(o)
	}
	for _, o := range nodes.globals {
		add(o)
	}
	for _, o := range nodes.formals {
		add(o)
	}
	for o := range nodes.foreign {
		add(o)
	}
	for _, o := range nodes.params {
		add(o)
	}
	for _, o := range nodes.loads {
		add(o)
	}
	if nodes.returnNode != nil {
		add(nodes.returnNode)
	}
	if nodes.unknownReturn != nil {
		add(nodes.unknownReturn)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].number < ordered[j].number })
	return ordered
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
	node = &Node{KindAlloc, g.globalNodes.getNewID(), fmt.Sprintf("new %s L:%d", shortTypeName, instr.Parent().Prog.Fset.Position(instr.Pos()).Line)}
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
	node = &Node{kind, g.globalNodes.getNewID(), kindStr + variable.Name()}
	g.variables[variable] = node
	return node
}

// The return node of a function, which represents the implicit or explicit variables
// that capture the returned values. There is one node per function.
func (g *NodeGroup) ReturnNode() *Node {
	if g.returnNode != nil {
		return g.returnNode
	}
	node := &Node{KindReturn, g.globalNodes.getNewID(), "return"}
	g.returnNode = node
	return node
}

// This node represents the return value of an unknown (unanalyzed) function. This is
// different from the return of a function that doesn't have a summary yet; this is
// for functions that will never be summarized. This should be fairly rare, as it is
// very conservative for soundness; functions should either be analyzed or have a
// manual summary written for them. It is safe to use the same node for all calls to
// unknown functions as long as the graph edges remain untyped.
func (g *NodeGroup) UnknownReturnNode() *Node {
	if g.unknownReturn != nil {
		return g.unknownReturn
	}
	node := &Node{KindUnknown, g.globalNodes.getNewID(), "unknown"}
	g.unknownReturn = node
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
	node = &Node{KindLoad, g.globalNodes.getNewID(), fmt.Sprintf("%s load L:%d", shortTypeName, instr.Parent().Prog.Fset.Position(instr.Pos()).Line)}
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
	node = &Node{KindParam, g.globalNodes.getNewID(), "pointee of " + param.Name()}
	g.params[param] = node
	return node
}

// Adds a foreign node to the node group. This currently just tracks which nodes are added so they can be iterated over.
// A different design would be to create a new node so that each NodeGroup is self-contained.
func (g *NodeGroup) AddForeignNode(n *Node) (changed bool) {
	if _, ok := g.foreign[n]; ok {
		return false
	}
	g.foreign[n] = struct{}{}
	return true
}

// Deref() is required because globals are not represented in a uniform way with
// parameters/locals/freevars. In the SSA form, a global is implicitly a pointer to the
// its type. So if we have a global decl:
//
//	var global *S
//
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
func (ea *functionAnalysisState) transferFunction(instr ssa.Instruction, g *EscapeGraph, verbose bool) {
	// Switch on the instruction to handle each kind of instructions.
	// Some instructions have sub-kinds depending on their arguments, or have alternate comma-ok forms.
	// If an instruction is handled, return. Otherwise, fall through to the end of the function to print
	// a warning about an unhandled instruction. When the set of instructions is complete, this should turn
	// into an error/panic.
	nodes := ea.nodes
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
		if lang.IsNillableType(instrType.Val.Type()) {
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
			if lang.IsNillableType(instrType.Type()) {
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
	case *ssa.Call:
		// Build the argument array, consisting of the nodes that are the concrete arguments
		// Nil nodes are used for things that aren't pointer-like, so that they line up with
		// the formal parameter definitions.
		args := make([]*Node, len(instrType.Call.Args))
		for i, arg := range instrType.Call.Args {
			if lang.IsNillableType(arg.Type()) {
				args[i] = nodes.ValueNode(arg)
			}
		}
		// For now, we just have one return value that is the merged representation of all of
		// them. For proper tuple-sensitive results, we would need to make this match the real
		// number of return values, and find out which extract operations we should assign the
		// results to.
		rets := []*Node{nodes.ValueNode(instrType)}
		if callee := instrType.Call.StaticCallee(); callee != nil {
			summary := ea.prog.summaries[callee]
			if summary != nil {
				// We can use the finalGraph pointer freely as it will never change after it is created
				summary.summaryUses[summaryUse{ea, instrType}] = summary.finalGraph
				g.Call(args, rets, summary.finalGraph)
				if verbose {
					ea.prog.logger.Printf("After call:\n%v", g.Graphviz())
				}
				return
			} else {
				if verbose {
					ea.prog.logger.Printf("Warning, %v is not a summarized function: treating as unknown call\n", callee.Name())
				}
			}
		} else {
			// TODO: support using multiple callees and using the pointer analysis to get them.
			if verbose {
				ea.prog.logger.Printf("Warning, %v is not a static call: treating as unknown call\n", instrType)
			}
		}
		// If we didn't find a summary or didn't know the callee, use the arbitrary function assumption.
		// Crucially, this is different from a function that will have a summary but we just haven't
		// seen yet (e.g. when there is recursion). If we haven't seen a function, then it will have the
		// initial lattice value (basically, the empty graph), and as the monotone framework loop proceeds,
		// will get more and more edges. This case, by contrast, imposes a fixed semantics: leak all the
		// arguments and return an object which may be arbitrary (and is therefore leaked).
		g.CallUnknown(args, rets)
		return
	case *ssa.Defer:
	case *ssa.Field:
		if lang.IsNillableType(instrType.Type()) {
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
		if lang.IsNillableType(instrType.Type().Underlying()) {
			gen := func() *Node { return nodes.LoadNode(instr, instrType.Type()) }
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
		}
		return
	case *ssa.MapUpdate:
		// TODO: refactor this into a generic store like .Load and .WeakAssign
		if lang.IsNillableType(instrType.Value.Type()) {
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
		if lang.IsNillableType(instrType.Key.Type()) {
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
		if lang.IsNillableType(instrType.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
		}
		return
	case *ssa.Convert:
		if lang.IsNillableType(instrType.Type()) {
			// TODO: conversion between string and []byte or []rune should be treated as an allocation
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
		}
		return
	case *ssa.ChangeInterface:
		g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.X.Type())
		return
	case *ssa.ChangeType:
		if lang.IsNillableType(instrType.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.X.Type())
		}
		return
	case *ssa.Phi:
		if lang.IsNillableType(instrType.Type()) {
			for _, v := range instrType.Edges {
				g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(v), instrType.Type())
			}
		}
		return
	case *ssa.Extract:
		if _, ok := instrType.Tuple.(*ssa.Phi); ok {
			panic("Extract from phi?")
		}
		if lang.IsNillableType(instrType.Type()) {
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
	if verbose {
		ea.prog.logger.Printf("Unhandled: (type: %s) %v\n", reflect.TypeOf(instr).String(), instr)
	}
}

type functionAnalysisState struct {
	function     *ssa.Function
	prog         *ProgramAnalysisState
	initialGraph *EscapeGraph                     // the graph on entry to the function. never mutated.
	nodes        *NodeGroup                       // the nodes used in these graphs
	blockEnd     map[*ssa.BasicBlock]*EscapeGraph // the monotone framework result at each basic block end
	finalGraph   *EscapeGraph                     // mutability: the finalGraph will never be mutated in place, so saving a reference without Clone() is safe
	worklist     []*ssa.BasicBlock                // persist the worklist so we can add basic blocks of function calls that change
	summaryUses  map[summaryUse]*EscapeGraph      // records uses of this summary in other functions, used to trigger re-analysis
}

// Used to record the position at which a function summary graph is used.
// The function here is a *functionAnalysisState rather than ssa.Function
// (or even just ssa.Instruction) to support context-sensitivity.
type summaryUse struct {
	function    *functionAnalysisState
	instruction ssa.Instruction
}

// Creates a new function analysis for the given function, tied to the given whole program analysis
func newfunctionAnalysisState(f *ssa.Function, prog *ProgramAnalysisState) (ea *functionAnalysisState) {
	nodes := NewNodeGroup(prog.globalNodes)
	initialGraph := NewEmptyEscapeGraph(nodes)
	for _, p := range f.Params {
		var formalNode *Node = nil
		if lang.IsNillableType(p.Type()) {
			paramNode := nodes.ParamNode(p)
			formalNode = nodes.ValueNode(p)
			initialGraph.AddEdge(formalNode, paramNode, true)
		}
		nodes.formals = append(nodes.formals, formalNode)
	}
	worklist := []*ssa.BasicBlock{}
	if len(f.Blocks) > 0 {
		worklist = append(worklist, f.Blocks[0])
	}
	return &functionAnalysisState{
		f,
		prog,
		initialGraph,
		nodes,
		make(map[*ssa.BasicBlock]*EscapeGraph),
		NewEmptyEscapeGraph(nodes),
		worklist,
		map[summaryUse]*EscapeGraph{},
	}
}

// Performs the monotone transfer function for a particular block, and returns
// whether the end graph changed. This function computes the merge of the predecessors,
// iterates over each instruction, and then stores the result (if different) into
// the blockEnd map.
func (ea *functionAnalysisState) ProcessBlock(bb *ssa.BasicBlock) (changed bool) {
	g := NewEmptyEscapeGraph(ea.nodes)
	if len(bb.Preds) == 0 {
		// Entry block uses the function-wide initial graph
		g.Merge(ea.initialGraph)
	} else {
		// Take the union of all our predecessors. Treat nil as no-ops; they will
		// be filled in later, and then the current block will be re-analyzed
		for _, pred := range bb.Preds {
			if predGraph := ea.blockEnd[pred]; predGraph != nil {
				g.Merge(predGraph)
			}
		}
	}
	for _, instr := range bb.Instrs {
		ea.transferFunction(instr, g, ea.prog.verbose)
	}
	if oldGraph, ok := ea.blockEnd[bb]; ok {
		if oldGraph.Matches(g) {
			return false
		}
	}
	ea.blockEnd[bb] = g
	return true
}

// Adds the block to the function's worklist, if it is not already present.
// After this call returns, block will definitely be on the worklist.
func (e *functionAnalysisState) addToBlockWorklist(block *ssa.BasicBlock) {
	found := false
	for _, entry := range e.worklist {
		if entry == block {
			found = true
		}
	}
	if !found {
		e.worklist = append(e.worklist, block)
	}
}

// An implementation of the convergence loop of the monotonic framework.
// Each block is processed, and if it's result changes the successors are added.
func (e *functionAnalysisState) RunForwardIterative() {
	if len(e.function.Blocks) == 0 {
		return
	}
	for len(e.worklist) > 0 {
		block := e.worklist[0]
		e.worklist = e.worklist[1:]
		if e.ProcessBlock(block) {
			for _, nextBlock := range block.Succs {
				e.addToBlockWorklist(nextBlock)
			}
		}
	}
}

// Compute the escape summary for a single function, independently of all other functions.
// Other functions are treated as arbitrary.
func EscapeSummary(f *ssa.Function) (graph *EscapeGraph) {
	prog := &ProgramAnalysisState{make(map[*ssa.Function]*functionAnalysisState), &globalNodeGroup{0}, false, nil}
	analysis := newfunctionAnalysisState(f, prog)
	resummarize(analysis)
	return analysis.finalGraph
}

// Contains the summaries for the entire program. Currently, this is just a simple
// wrapper around a map of function to analysis results, but it will likely need to expand
// to work with the taint analysis.
type ProgramAnalysisState struct {
	summaries   map[*ssa.Function]*functionAnalysisState
	globalNodes *globalNodeGroup
	verbose     bool
	logger      *log.Logger
}

// (Re)-compute the escape summary for a single function. This will re-run the analysis
// monotone framework loop and update the finalGraph. Returns true if the finalGraph
// changed from its prior version.
func resummarize(analysis *functionAnalysisState) (changed bool) {
	analysis.RunForwardIterative()
	returnResult := NewEmptyEscapeGraph(analysis.nodes)
	returnNode := analysis.nodes.ReturnNode()
	for block, blockEndState := range analysis.blockEnd {
		if len(block.Instrs) > 0 {
			if retInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return); ok {
				returnResult.Merge(blockEndState)
				for _, rValue := range retInstr.Results {
					if lang.IsNillableType(rValue.Type()) {
						returnResult.WeakAssign(returnNode, analysis.nodes.ValueNode(rValue), rValue.Type())
					}
				}
			}
		}
	}
	same := analysis.finalGraph != nil && analysis.finalGraph.Matches(returnResult)
	// The returnResult is always a fresh graph rather than mutating the old one, so we preserve the invariant
	// that the finalGraph never mutates
	analysis.finalGraph = returnResult
	return !same
}

// This just prints the escape summary for each function in the callgraph.
// This interface will change substaintially when intraprocedural analysis is finalized.
func EscapeAnalysis(state *dataflow.AnalyzerState, root *callgraph.Node) (*ProgramAnalysisState, error) {
	prog := &ProgramAnalysisState{
		summaries:   make(map[*ssa.Function]*functionAnalysisState),
		verbose:     state.Config.Verbose(),
		globalNodes: &globalNodeGroup{0},
		logger:      state.Logger.GetDebug(),
	}
	// Find all the nodes that are in the main package, and thus treat everything else as unsummarized
	nodes := []*callgraph.Node{}
	for f, node := range state.PointerAnalysis.CallGraph.Nodes {
		if len(f.Blocks) > 0 {
			pkg := lang.PackageTypeFromFunction(f)
			if pkg == nil || state.Config.MatchPkgFilter(pkg.Path()) || state.Config.MatchPkgFilter(pkg.Name()) {
				prog.summaries[f] = newfunctionAnalysisState(f, prog)
				nodes = append(nodes, node)
			}
		}
	}

	succ := func(n *callgraph.Node) []*callgraph.Node {
		succs := []*callgraph.Node{}
		for _, e := range n.Out {
			succs = append(succs, e.Callee)
		}
		return succs
	}

	// Build the worklist in reverse topological order, so that summaries are computed
	// before the functions that use them. This relies on the worklist being pulled
	// from at the end. We need to work from the append side so that when we are
	// processing an SCC, the functions are re-analyzed before moving on to the next
	// SCC. If we tracked the worklist by SCC, we could make this even more efficient
	// by putting the node not at top of the stack but at the bottom of the current
	// SCC so that other members of the SCC are analyzed first.
	worklist := make([]*functionAnalysisState, len(nodes))
	nextIndex := len(worklist) - 1
	for _, scc := range graphutil.StronglyConnectedComponents(nodes, succ) {
		for _, n := range scc {
			if summary, ok := prog.summaries[n.Func]; ok {
				worklist[nextIndex] = summary
				nextIndex -= 1
			}
		}
	}
	if nextIndex != -1 {
		panic("expected reverse to be complete")
	}
	// The main worklist algorithm. Reanalyze each function, putting any function(s) that need to be reanalyzed back on
	// the list
	for len(worklist) > 0 {
		summary := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		funcName := summary.function.Name()
		state.Logger.Debugf("Analyzing %v\n", funcName)
		changed := resummarize(summary)
		state.Logger.Tracef("Func %s is (changed=%v):\n%s\n", funcName, changed, summary.finalGraph.GraphvizLabel(funcName))
		// Iterate over the places where this summary is used, and schedule them to be re-analyzed
		for location, graphUsed := range summary.summaryUses {
			if !summary.finalGraph.Matches(graphUsed) {
				location.function.addToBlockWorklist(location.instruction.Block())
				// Add to the worklist if it isn't already there
				found := false
				for _, entry := range worklist {
					if entry == location.function {
						found = true
						break
					}
				}
				if !found {
					worklist = append(worklist, location.function)
				}
			}
		}
	}
	// Print out the final graphs for debugging purposes
	if prog.verbose {
		for f := range state.PointerAnalysis.CallGraph.Nodes {
			summary := prog.summaries[f]
			if summary != nil && summary.nodes != nil && f.Pkg != nil {
				if "main" == f.Pkg.Pkg.Name() {
					state.Logger.Debugf("Func %s summary is:\n%s\n", f.String(), summary.finalGraph.GraphvizLabel(f.String()))
				}
			}
		}
	}
	return prog, nil
}
