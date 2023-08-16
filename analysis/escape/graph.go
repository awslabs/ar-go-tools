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

package escape

import (
	"bytes"
	"fmt"
	"go/types"
	"reflect"
	"sort"
	"strings"

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

type EscapeStatus uint8

const (
	Local   EscapeStatus = 0
	Escaped EscapeStatus = 1
	Leaked  EscapeStatus = 2
)

// A node represents the objects tracked by the escape analysis.
// Nodes represent local variables, globals, parameters, and heap
// cells of various kinds (maps, slices, arrays, structs)
type Node struct {
	kind      NodeKind
	number    int    // For unambiguous debug printing
	debugInfo string // where this node comes from
}

func (n *Node) String() string {
	return fmt.Sprintf("%d<%s>", n.number, n.debugInfo)
}

// Certain nodes are intrinsically external: parameters, loads, and globals.
// Note that this doesn't include ParamVars, which are the (local) pointers
// at the external objects.
func (n *Node) IntrinsicEscape() EscapeStatus {
	switch n.kind {
	case KindParam, KindLoad:
		return Escaped
	case KindGlobal, KindUnknown:
		return Leaked
	default:
		return Local
	}
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
	// edges  map[*Node]map[*Node]bool
	internalEdges map[*Node]map[*Node]bool
	externalEdges map[*Node]map[*Node]bool
	status        map[*Node]EscapeStatus
	nodes         *NodeGroup
}

// NewEmptyEscapeGraph produces an empty graph, which is also the unit of Merge() below
func NewEmptyEscapeGraph(nodes *NodeGroup) *EscapeGraph {
	gg := &EscapeGraph{
		make(map[*Node]map[*Node]bool),
		make(map[*Node]map[*Node]bool),
		make(map[*Node]EscapeStatus),
		nodes,
	}
	return gg
}

// Clones a graph, but preserves node identities between the two graphs.
func (g *EscapeGraph) Clone() *EscapeGraph {
	gg := NewEmptyEscapeGraph(g.nodes)
	for k, v := range g.externalEdges {
		m := make(map[*Node]bool, len(v))
		for k2, v2 := range v {
			m[k2] = v2
		}
		gg.externalEdges[k] = m
	}
	for k, v := range g.internalEdges {
		m := make(map[*Node]bool, len(v))
		for k2, v2 := range v {
			m[k2] = v2
		}
		gg.internalEdges[k] = m
	}
	for k, v := range g.status {
		gg.status[k] = v
	}
	return gg
}

type Edge struct {
	src        *Node
	dest       *Node
	isInternal bool
}

// Edges(s, d, e, i) finds all the edges from s to d that are external (if e) and internal (if i).
// Either or s or d may be nil, in which case they act as a wild card. To find all the edges from
// src to all nodes via only internal edges, do:
//
//	g.Edges(src, nil, false, true).
//
// To iterate over the result, use a loop like:
//
//	    for _, e := range g.Edges(src, nil, false, true) {
//			   fmt.Printf("Found %v", e.dest)
//	    }
//
// If both includeExternal and includeInteral are false, the result will always be empty. This method
// is convenient, but may not be the most efficient.
func (g *EscapeGraph) Edges(src, dest *Node, includeExternal, includeInternal bool) []*Edge {
	edges := make([]*Edge, 0, 1)
	if src != nil {
		if includeExternal {
			for d := range g.externalEdges[src] {
				if dest == nil || dest == d {
					edges = append(edges, &Edge{src, d, false})
				}
			}
		}
		if includeInternal {
			for d := range g.internalEdges[src] {
				if dest == nil || dest == d {
					edges = append(edges, &Edge{src, d, true})
				}
			}
		}
	} else {
		if includeExternal {
			for s := range g.externalEdges {
				for d := range g.externalEdges[s] {
					if dest == nil || dest == d {
						edges = append(edges, &Edge{s, d, false})
					}
				}
			}
		}
		if includeInternal {
			for s := range g.internalEdges {
				for d := range g.internalEdges[s] {
					if dest == nil || dest == d {
						edges = append(edges, &Edge{s, d, true})
					}
				}
			}
		}
	}
	return edges
}

// Pointees returns the set of nodes (as a map to empty struct) that are pointed to
// by src directly by any type of edge.
func (g *EscapeGraph) Pointees(src *Node) map[*Node]struct{} {
	pointees := make(map[*Node]struct{}, 4)
	for d := range g.externalEdges[src] {
		pointees[d] = struct{}{}
	}
	for d := range g.internalEdges[src] {
		pointees[d] = struct{}{}
	}
	return pointees
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
	if addr.kind == KindGlobal {
		return map[*Node]bool{addr: true}
	}
	addrPointees := map[*Node]bool{}
	for _, e := range g.Edges(addr, nil, true, true) {
		addrPointees[e.dest] = true
	}
	return addrPointees
}

// Debug returns a (multi-line) string representation suitable for debug printing.
// Not very visual, but easier to read in a terminal. See also Graphviz() below.
func (g *EscapeGraph) Debug() string {
	out := bytes.NewBuffer([]byte{})
	ordered := g.nodes.AllNodes()
	for _, v := range ordered {
		fmt.Fprintf(out, "%v -> ", v.number)
		first := true
		for n := range g.Pointees(v) {
			if !first {
				fmt.Fprintf(out, ", ")
			}
			first = false
			fmt.Fprintf(out, "%d", n.number)
		}
		statusString := ""
		if g.status[v] == Escaped {
			statusString = ", *Escaped"
		}
		if g.status[v] == Leaked {
			statusString = ", *Leaked"
		}
		fmt.Fprintf(out, "    <%v>%s\n", v.debugInfo, statusString)
	}

	return out.String()
}

// Graphviz returns a (multi-line) dot/graphviz input describing the graph.
func (g *EscapeGraph) Graphviz() string {
	return g.GraphvizLabel("")
}

// GraphvizLabel is like Graphvis, but adds a label to the graph; useful
// for e.g. displaying the function being analyzed.
//
//gocyclo:ignore
func (g *EscapeGraph) GraphvizLabel(label string) string {
	out := bytes.NewBuffer([]byte{})
	fmt.Fprintf(out, "digraph { // start of digraph\nrankdir = LR;\n")
	fmt.Fprintf(out, "graph[label=\"%s\"];\n", label)
	fmt.Fprintf(out, "subgraph {\nrank=same;\n")
	prevInVarBlock := -1
	ordered := []*Node{}
	for k := range g.status {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].number < ordered[j].number })

	for _, v := range ordered {
		if v.kind == KindVar || v.kind == KindParamVar || v.kind == KindReturn {
			extra := "shape=rect style=rounded width=0 height=0 margin=0.05 "
			if g.status[v] >= Escaped {
				extra += " style=\"dashed,rounded\""
			}
			if g.status[v] >= Leaked {
				extra += " peripheries=2"
			}
			escaped := strings.ReplaceAll(strings.ReplaceAll(v.debugInfo, "\\", "\\\\"), "\"", "\\\"")
			fmt.Fprintf(out, "%d [label=\"%s\" %s];\n", v.number, escaped, extra)
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
			if g.status[v] >= Escaped {
				extra += " style=dashed"
			}
			if g.status[v] >= Leaked {
				extra += " peripheries=2"
			}
			escaped := strings.ReplaceAll(strings.ReplaceAll(v.debugInfo, "\\", "\\\\"), "\"", "\\\"")
			fmt.Fprintf(out, "%d [label=\"%s\" %s];\n", v.number, escaped, extra)
		}
		for _, e := range g.Edges(v, nil, true, true) {
			extra := ""
			if !e.isInternal {
				extra = "style=dashed penwidth=2"
			}
			fmt.Fprintf(out, "%d -> %d [%s];\n", e.src.number, e.dest.number, extra)
		}
	}

	fmt.Fprintf(out, "} // end of digraph\n")
	return out.String()
}

// AddEdge adds an edge from base to dest. isInternal (almost always `true`) signals whether
// this is an internal edge (created during the current function) or external edge
// (possibly existed before the current function).
func (g *EscapeGraph) AddEdge(base *Node, dest *Node, isInternal bool) (changed bool) {
	edges := g.externalEdges
	if isInternal {
		edges = g.internalEdges
	}
	if m, ok := edges[base]; ok {
		if _, ok := m[dest]; ok {
			return false
		}
		g.AddNode(dest)
		m[dest] = true
	} else {
		g.AddNode(base)
		edges[base] = map[*Node]bool{dest: true}
		g.AddNode(dest)
	}
	// We added a new edge, so recompute closure
	g.computeEdgeClosure(base, dest)
	return true
}

// AddNode, Ensures g has an entry for n.
func (g *EscapeGraph) AddNode(n *Node) (changed bool) {
	if _, ok := g.status[n]; !ok {
		g.internalEdges[n] = map[*Node]bool{}
		g.externalEdges[n] = map[*Node]bool{}
		g.status[n] = n.IntrinsicEscape()
		return true
	}
	return false
}

func (g *EscapeGraph) computeEdgeClosure(a, b *Node) {
	if g.status[a] > g.status[b] {
		g.status[b] = g.status[a]
	} else {
		return
	}
	worklist := []*Node{b}
	for len(worklist) > 0 {
		node := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		nodeStatus := g.status[node]
		for succ := range g.Pointees(node) {
			if nodeStatus > g.status[succ] {
				g.status[succ] = nodeStatus
				worklist = append(worklist, succ)
			}
		}
	}
}

func (g *EscapeGraph) JoinNodeStatus(a *Node, s EscapeStatus) {
	if s > g.status[a] {
		g.status[a] = s
	} else {
		return
	}
	for n := range g.Pointees(a) {
		g.computeEdgeClosure(a, n)
	}
}

// Applies the weak-assignment operation `dest = src`. Basically, ensures that
// dest points to whatever src points to. Weak here means that it does not erase
// any existing edges from dest
func (g *EscapeGraph) WeakAssign(dest *Node, src *Node, t types.Type) {
	edgePointees := g.Deref(src)
	g.AddNode(dest)
	for e := range edgePointees {
		g.AddEdge(dest, e, true)
	}
}

// Load applies the load operation `valNode = *addrNode` and modifies g.
// This is a generalized operation: it also applies to reading from slices, maps, globals, etc.
// generateLoadNode is called to lazily create a node if the load can happen against an
// external object; this can't be determined a priori, and we don't want to create a load node
// unless necessary.
func (g *EscapeGraph) Load(valNode *Node, addrNode *Node, generateLoadNode func() *Node) {
	var loadNode *Node
	// Nodes are addr ->* addrPointee ->* doublePointee
	// val = *addr means we need to add edges from val to whatever node(s) *addr (i.e. all the addrPointees)'
	// points to. The addrPointees are the nodes that addr points to, and the doublePointees are collectively
	// everything that *addr points to. Thus we need to collect all double pointees and add edges
	// from val to these nodes.
	for addrPointee := range g.Deref(addrNode) {
		g.AddNode(addrPointee)
		// This is not .Deref(addrPointee) because the global is no longer being treated as an implicit pointer
		// in the ssa representation. Now, global nodes are treated the same as any other memory node, such as
		// structs, maps, etc.
		for doublePointee := range g.Pointees(addrPointee) {
			g.AddEdge(valNode, doublePointee, true)
		}
		// if addrPointee is an escaped node, we need to add the load node
		if g.status[addrPointee] > Local {
			if loadNode == nil {
				loadNode = generateLoadNode()
			}
			g.AddEdge(valNode, loadNode, true)
			g.AddEdge(addrPointee, loadNode, false)
		}
	}
	// TODO: for load operations, if the pointer node itself (not just its pointee) is external then we have a
	// problem, as it will also need a load node. This may not occur depending on how the SSA is constructed, i.e.
	// if we only have e.g. instrType.X represented by a local variable (which will never be external).
}

// Stores the pointer-like value valNode into the object(s) pointed to by addrNode
// Generalizes stores (*p = q) to include map updates (m[k] = v), channel sends,
// and other operations that need to write to a "field" of the pointees of addr.
func (g *EscapeGraph) Store(addrNode, valNode *Node, tp types.Type) {
	// Store the value into all the possible aliases of *addr
	for addrPointee := range g.Deref(addrNode) {
		g.WeakAssign(addrPointee, valNode, tp)
	}
}

// Merge computes the union of this graph with another, used at e.g. the join-points of a dataflow graph.
// Modifies g in-place.
func (g *EscapeGraph) Merge(h *EscapeGraph) {
	for _, e := range h.Edges(nil, nil, true, true) {
		g.AddEdge(e.src, e.dest, e.isInternal)
	}
	for node, s := range h.status {
		g.JoinNodeStatus(node, s)
	}
}

// Computes the result of splicing in the summary (callee) of the callee's graph.
// args are the nodes corresponding to the caller's actual parameters at the callsite (nil if not pointer-like)
// rets are the nodes corresponding to the caller values to assign the results to (nil if not pointer-like)
// nodes is the NodeGroup for the caller, and also therefore the graph g
// summary is the summary of the called function.
// summaryNodes is the nodeGroup in the context of the called function
//
//gocyclo:ignore
func (g *EscapeGraph) Call(args []*Node, freeVarsPointees [][]*Node, rets []*Node, callee *EscapeGraph) {
	pre := g.Clone()
	// u maps nodes in summary to the nodes in the caller
	u := map[*Node]map[*Node]struct{}{}
	// deferredReps are used to ensure one of the rules triggers consistently
	deferredReps := map[*Node]map[*Node]struct{}{}

	worklist := []struct{ x, y *Node }{}
	addUEdge := func(x, y *Node) {
		if m, ok := u[x]; ok {
			if _, ok := m[y]; ok {
				return
			}
			m[y] = struct{}{}
		} else {
			u[x] = map[*Node]struct{}{y: {}}
		}
		// fmt.Printf("Adding U edge %v -> %v\n", x, y)
		worklist = append(worklist, struct{ x, y *Node }{x, y})
	}
	addDeferredRep := func(x, y *Node) {
		if m, ok := deferredReps[x]; ok {
			m[y] = struct{}{}
		} else {
			deferredReps[x] = map[*Node]struct{}{y: {}}
		}
	}

	// Connect argument and return nodes
	if len(args) != len(callee.nodes.formals) {
		panic("Incorrect number of arguments")
	}
	for i, formal := range callee.nodes.formals {
		if (args[i] == nil) != (formal == nil) {
			panic("Incorrect nil-ness of corresponding parameter nodes")
		}
		if formal != nil {
			for actualObject := range pre.Pointees(args[i]) {
				// This gets the parameter node, i.e. the node representing the abstract pointee of the
				// formal: param in formal ----> param. Because parameters are not assigned to, this will
				// always be the same as in the initial graph. This loop should thus only execute the body once.
				for paramNode := range callee.Pointees(formal) {
					addUEdge(paramNode, actualObject)
				}
			}
		}
	}
	for i, freevar := range callee.nodes.freevars {
		if (freeVarsPointees[i] == nil) != (freevar == nil) {
			panic("Incorrect nil-ness of corresponding free var nodes")
		}
		if freevar != nil {
			if len(freeVarsPointees[i]) == 0 {
				panic("Invariant: (pointer-like) free vars must always have at least one node representative")
			}
			for innerPointee := range callee.Pointees(freevar) {
				// As in the parameter case, this connects the pointee of the free var (the free param object)
				// with the objects that it could be in the caller
				for _, outerPointee := range freeVarsPointees[i] {
					addUEdge(innerPointee, outerPointee)
				}
			}
		}
	}
	for i, ret := range rets {
		if ret != nil {
			for returnedNode := range callee.Pointees(callee.nodes.ReturnNode(i)) {
				for actualObject := range pre.Pointees(ret) {
					addUEdge(returnedNode, actualObject)
				}
			}
			addUEdge(callee.nodes.ReturnNode(i), ret)
		}
	}

	// Process edges in worklist
	for len(worklist) > 0 {
		edgeToProcess := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		base, rep := edgeToProcess.x, edgeToProcess.y // base is in callee, rep is in g

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

		// Alloc nodes did not exist when the call occurred, so these edges cannot point to a node in the original
		if base.kind != KindAlloc {
			for _, baseEdge := range callee.Edges(base, nil, true, true) {
				if !baseEdge.isInternal {
					// This would the following, but it is very slow according to the profiler:
					// for _, repEdge := range pre.Edges(rep, nil, false, true) {
					// Instead, we break the abstraction a bit and access the map directly
					for v := range pre.internalEdges[rep] {
						addUEdge(baseEdge.dest, v)
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
		// If the right u edge is already present, then when we process base/rep, we will
		// add the right thing. But if the left edge is added first, then we will miss adding
		// an edge as there will be no edges from y -> x. Therefore, we add a "deferredRep"
		// edge from y to rep. If y -> x is ever added later, then the case below will trigger
		// and the edge will be completed.
		for _, edge := range callee.Edges(base, nil, false, true) {
			// y is edge.dest
			for x := range u[edge.dest] {
				// fmt.Printf("Propogating internal edge %v %v\n", rep, x)
				g.AddEdge(rep, x, true)
			}
			addDeferredRep(edge.dest, rep)
		}

		// The same as above, but where base is the y in the above diagram
		// There must have been a previous u edge added from b to r. The
		// dR (deferredReps) edge tells us what r(s) we need to add edges
		// from. We can unconditionally add the edge as adding the deferredRep
		// edge already checked the appropriate conditions
		// r          rep
		// |  \_ dR   |
		// | u   \_   | u
		// |        \ |
		// b  ------> base
		// We do not keep track of what b was, but it must have existed.
		for r := range deferredReps[base] {
			// fmt.Printf("Adding deferred internal edge %v %v\n", r, rep)
			g.AddEdge(r, rep, true)
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
		for _, edge := range callee.Edges(base, nil, true, true) {
			if edge.isInternal && (edge.dest.kind == KindAlloc || edge.dest.kind == KindUnknown) {
				// fmt.Printf("Adding alloc node %v\n", edge.dest)
				g.nodes.AddForeignNode(edge.dest)
				g.AddNode(edge.dest)
				addUEdge(edge.dest, edge.dest)
			}
		}

		// propagate load nodes that are referenced by escaped nodes
		// Adds node load to g, and adds the mapping edge u' and edge rep - -> load'
		// rep  - - -> load'
		//  |           |
		//  | u         | u'
		//  |           |
		// base - - -> load
		// Rep is required to be escaped.

		if status, ok := pre.status[rep]; !ok || status != Local {
			for _, edge := range callee.Edges(base, nil, true, true) {
				if !edge.isInternal || base.kind == KindParamVar || base.kind == KindGlobal {
					g.AddNode(edge.dest)
					g.nodes.AddForeignNode(edge.dest)
					// fmt.Printf("Adding load edge %v %v\n", rep, edge.dest)
					g.AddEdge(rep, edge.dest, false)
					addUEdge(edge.dest, edge.dest)
				}
			}
		}
		// Propagating "escaped" information is tricky. We need to make a distinction between things
		// that could have escaped to the heap, and just things that are parameters/loads from the callee's
		// perspective. This means that we propagate "leaked" along u edges but not "escaped."
		if callee.status[base] == Leaked {
			if g.status[rep] < Leaked {
				g.JoinNodeStatus(rep, Leaked)
			}
		}
	}
}

// CallUnknown Computes the result of calling an unknown function.
// An unknown function has no bound on its allow semantics. This means that the
// arguments are assumed to leak, and the return value is treated similarly to a
// load node, except it can never be resolved with arguments like loads can be.
func (g *EscapeGraph) CallUnknown(args []*Node, rets []*Node) {
	for _, arg := range args {
		for n := range g.Pointees(arg) {
			g.JoinNodeStatus(n, Leaked)
		}
	}
	for _, ret := range rets {
		g.AddEdge(ret, g.nodes.UnknownReturnNode(), true)
	}
}

// CallBuiltin computes the result of calling an builtin. The name (len, copy, etc)
// and the effective type can be retrieved from the ssa.Builtin. An unknown function
// has no bound on its allow semantics. This means that the arguments are assumed
// to leak, and the return value is treated similarly to a load node, except it can
// never be resolved with arguments like loads can be.
//
//gocyclo:ignore
func (g *EscapeGraph) CallBuiltin(instr ssa.Instruction, builtin *ssa.Builtin, args []*Node, rets []*Node) error {
	switch builtin.Name() {
	case "len": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "cap": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "close": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "complex": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "real": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "imag": // No-op, as does not leak and the return value is not pointer-like
		return nil
	case "print": // No-op, as does not leak and no return value
		return nil
	case "println": // No-op, as does not leak and no return value
		return nil
	case "recover": // We don't track panic values, so treat like an unknown call
		g.CallUnknown(args, rets)
		return nil
	case "ssa:wrapnilchk": // treat as identity fucntion
		g.WeakAssign(rets[0], args[0], nil)
		return nil
	case "delete": // treat as noop, as we don't actually erase information
		return nil
	case "append":
		// ret = append(slice, x)
		// slice is a slice, and so is x.
		// Basically, we copy all the outedges from *x to *slice
		// Then we copy all the edges from *slice to a new allocation node, which
		// represents the case where there wasn't enough space (we don't track enough
		// information to distinguish these possibilities ourselves.)
		if len(args) != 2 {
			panic("Append must have exactly 2 args")
		}
		sliceArg, xArg, ret := args[0], args[1], rets[0]
		sig := builtin.Type().(*types.Signature)
		sliceType := sig.Results().At(0).Type().Underlying().(*types.Slice)
		// First, simulate the write to the array
		for baseArray := range g.Pointees(sliceArg) {
			for xArray := range g.Pointees(xArg) {
				g.WeakAssign(baseArray, xArray, sliceType.Elem())
			}
			// The return value can be one of the existing backing arrays
			g.AddEdge(ret, baseArray, true)
		}
		// Then, simulate an allocation. This happens second so we pick up the newly added edges
		allocArray := g.nodes.AllocNode(instr, types.NewArray(sliceType.Elem(), -1))
		for baseArray := range g.Pointees(sliceArg) {
			g.WeakAssign(allocArray, baseArray, sliceType.Elem())
		}
		g.AddEdge(ret, allocArray, true)
		return nil
	case "copy":
		// copy(dest, src)
		// Both arguments are slices: copy all the outedges from *src to *dest
		// Ignore the return value
		// Special case: src is a string. Do nothing in that case, as we don't track
		// characters. This is handled by not having any edges from a nil srcArg.
		if len(args) != 2 {
			panic("Copy must have exactly 2 args")
		}
		destArg, srcArg := args[0], args[1]
		sig := builtin.Type().(*types.Signature)
		sliceType := sig.Params().At(0).Type().Underlying().(*types.Slice)
		// First, simulate the write to the array
		for destArray := range g.Pointees(destArg) {
			for srcArray := range g.Pointees(srcArg) {
				g.WeakAssign(destArray, srcArray, sliceType.Elem())
			}
		}
		return nil
	case "String", "StringData", "Slice", "SliceData", "Add":
		return fmt.Errorf("unsafe operation %v\n", builtin.Name())
	default:
		return fmt.Errorf("unhandled: %v\n", builtin.Name())
	}
}

// Matches checks if two graphs are equal. Used for convergence checking.
func (g *EscapeGraph) Matches(h *EscapeGraph) bool {
	// TODO: This may become a performance bottleneck
	return reflect.DeepEqual(g.internalEdges, h.internalEdges) &&
		reflect.DeepEqual(g.externalEdges, h.externalEdges) &&
		reflect.DeepEqual(g.status, h.status)
}

// LessEqual returns true if g is less than or equal to h in the lattice ordering
// associated with the monotone framework. This function is useful for detecting convergence
// problems and correctness bugs.
func (g *EscapeGraph) LessEqual(h *EscapeGraph) (isLessEq bool, reason string) {
	// In order for g <= h, the set of edges of g must all be contained in h, and the
	// nodes statuses must be pairwise less or equal.

	for _, gEdge := range g.Edges(nil, nil, true, true) {
		if len(h.Edges(gEdge.src, gEdge.dest, !gEdge.isInternal, gEdge.isInternal)) == 0 {
			return false, fmt.Sprintf("missing edge %v -> %v (internal: %v)", gEdge.src, gEdge.dest, gEdge.isInternal)
		}
	}
	for node, g_status := range g.status {
		if h_status, ok := h.status[node]; ok {
			if g_status > h_status {
				return false, "mode status is not leq"
			}
		} else {
			return false, "node not present"
		}
	}
	return true, ""
}

type globalNodeGroup struct {
	nextNode int
	function map[*Node]*ssa.Function
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
	freevars      []*Node
	returnNodes   map[int]*Node
	nilNode       *Node
	unusedNode    *Node
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
		make([]*Node, 0),
		make(map[int]*Node),
		nil,
		nil,
		nil,
		globalNodes,
	}
}

// AllNodes returns all nodes in the group, sorted by their number.
func (nodes *NodeGroup) AllNodes() []*Node {
	ordered := []*Node{}
	alreadyAdded := map[*Node]bool{}
	add := func(o *Node) {
		if o == nil {
			panic("nil *Node")
		}
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
		if o != nil { // nil means not-pointer-like, i.e. integer
			add(o)
		}
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
	for _, node := range nodes.returnNodes {
		add(node)
	}
	if nodes.unknownReturn != nil {
		add(nodes.unknownReturn)
	}
	if nodes.nilNode != nil {
		add(nodes.nilNode)
	}
	if nodes.unusedNode != nil {
		add(nodes.unusedNode)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].number < ordered[j].number })
	return ordered
}

// AllocNode creates a node that represents an allocation, such as &S{}, make([]int, 3),
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
	node = &Node{KindAlloc, g.globalNodes.getNewID(), fmt.Sprintf("new %s L:%d", shortTypeName,
		instr.Parent().Prog.Fset.Position(instr.Pos()).Line)}
	g.allocs[instr] = node
	return node
}

// Value node returns a node that represents a ssa.Value. Most such values are virtual registers created
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
			return g.NilNode()
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

// ReturnNode returns the return node of a function, which represents all the
// implicit or explicit variables that capture the returned values. There is
// one node per function.
func (g *NodeGroup) ReturnNode(i int) *Node {
	if node, ok := g.returnNodes[i]; ok {
		return node
	}

	node := &Node{KindReturn, g.globalNodes.getNewID(), fmt.Sprintf("return %v", i)}
	g.returnNodes[i] = node
	return node
}

// NilNode returns the nil node of a function, which represents a pointer that is always nil
// Invariant: should not have any out edges (i.e. should never be assigned to)
func (g *NodeGroup) NilNode() *Node {
	if g.nilNode != nil {
		return g.nilNode
	}
	node := &Node{KindVar, g.globalNodes.getNewID(), "nil"}
	g.nilNode = node
	return node
}

// UnusedNode returns the unused pointer node, which represents a node that you don't care about.
// Can be used to represent the `_` identifier. Can have out edges, but these
// edges should never be used because nothing will read from `_`.
func (g *NodeGroup) UnusedNode() *Node {
	if g.unusedNode != nil {
		return g.unusedNode
	}
	node := &Node{KindVar, g.globalNodes.getNewID(), "_"}
	g.unusedNode = node
	return node
}

// UnknownReturnNode represents the return value of an unknown (unanalyzed) function. This is
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

// LoadNode creates a load node, which represents the object(s) that are potentially
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
	node = &Node{KindLoad, g.globalNodes.getNewID(), fmt.Sprintf("%s load L:%d", shortTypeName,
		instr.Parent().Prog.Fset.Position(instr.Pos()).Line)}
	g.loads[instr] = node
	return node
}

// ParamNode creates a node for the initial pointee of a parameter/freevar. This is different from the var node of the pointer,
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

// AddForeignNode adds a foreign node to the node group. This currently just tracks which nodes are added so they can be iterated over.
// A different design would be to create a new node so that each NodeGroup is self-contained.
func (g *NodeGroup) AddForeignNode(n *Node) (changed bool) {
	if _, ok := g.foreign[n]; ok {
		return false
	}
	g.foreign[n] = struct{}{}
	return true
}

func (g *EscapeGraph) CloneReachable(roots []*Node) *EscapeGraph {
	reachable := make(map[*Node]bool, len(g.status))
	worklist := make([]*Node, 0, len(roots))

	for _, r := range roots {
		reachable[r] = true
		worklist = append(worklist, r)
	}
	for len(worklist) > 0 {
		n := worklist[len(worklist)-1]
		worklist = worklist[0 : len(worklist)-1]
		for d := range g.externalEdges[n] {
			if !reachable[d] {
				reachable[d] = true
				worklist = append(worklist, d)
			}
		}
		for d := range g.internalEdges[n] {
			if !reachable[d] {
				reachable[d] = true
				worklist = append(worklist, d)
			}
		}
	}
	// fmt.Printf("Reachable: %v\n", reachable)
	gg := NewEmptyEscapeGraph(g.nodes)
	for k, v := range g.externalEdges {
		if !reachable[k] {
			continue
		}
		m := make(map[*Node]bool, len(v))
		for k2, v2 := range v {
			m[k2] = v2
		}
		gg.externalEdges[k] = m
	}
	for k, v := range g.internalEdges {
		if !reachable[k] {
			continue
		}
		m := make(map[*Node]bool, len(v))
		for k2, v2 := range v {
			m[k2] = v2
		}
		gg.internalEdges[k] = m
	}
	for k, v := range g.status {
		if reachable[k] {
			gg.status[k] = v
		}
	}
	return gg
}
