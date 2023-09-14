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

// EscapeStatus represents whether a node is Local, Escaped, or Leaked
type EscapeStatus uint8

const (
	Local   EscapeStatus = 0
	Escaped EscapeStatus = 1
	Leaked  EscapeStatus = 2
)

// edgeFlags are used when representing an edge, as we can pack multiple edges into the same byte
type edgeFlags uint8

const (
	EdgeInternal edgeFlags = 1 << iota
	EdgeExternal
	EdgeSubnode // currently unused
)

// A node represents the objects tracked by the escape analysis. Nodes represent local variables,
// globals, parameters, and heap cells of various kinds (maps, slices, arrays, structs)
type Node struct {
	kind      NodeKind
	number    int    // For unambiguous debug printing
	debugInfo string // where this node comes from
}

func (n *Node) String() string {
	return fmt.Sprintf("%d<%s>", n.number, n.debugInfo)
}

// IntrinsicEscape returns the intrinsic status of a node. Certain nodes are intrinsically external:
// parameters, loads, and globals. Note that this doesn't include ParamVars, which are the (local)
// pointers at the external objects. Other nodes are intrinsically escaped, as they represent
// parameters.
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

// The escape graph is the element of the monotone framework and the primary focus of the escape
// analysis. The graph represents edges as src -> dest -> isInternal. The final bool is semantically
// significant: the edges are labeled as internal or external. Escaped is a set of nodes that are
// not known to be local in the current context; they are treated differently on load operations.
// Leaked is a subset of escaped nodes that have (possibly) leaked out of the current goroutine,
// whereas escaped nodes may still be local depending on the calling context. The major operations
// on escape graphs are to AddEdge()s, (plus composite operations like Load, WeakAssign), Merge(),
// and compare with Matches().
type EscapeGraph struct {
	edges  map[*Node]map[*Node]edgeFlags
	status map[*Node]EscapeStatus
	nodes  *NodeGroup
}

// Represents a single atomic edge within the escape graph. Nodes connected by more than one kind of
// edge will produce multiple Edge's when queried.
type Edge struct {
	src        *Node
	dest       *Node
	isInternal bool
}

// NewEmptyEscapeGraph produces an empty graph, which is also the unit of Merge() below
func NewEmptyEscapeGraph(nodes *NodeGroup) *EscapeGraph {
	gg := &EscapeGraph{
		// make(map[*Node]map[*Node]map[Edge]bool),
		make(map[*Node]map[*Node]edgeFlags),
		make(map[*Node]EscapeStatus),
		nodes,
	}
	return gg
}

// Clones a graph, preserving node identities between the two graphs.
func (g *EscapeGraph) Clone() *EscapeGraph {
	gg := NewEmptyEscapeGraph(g.nodes)
	for src, outEdges := range g.edges {
		newOutEdges := make(map[*Node]edgeFlags, len(outEdges))
		for dest, f := range outEdges {
			newOutEdges[dest] = f
		}
		gg.edges[src] = newOutEdges
	}
	for k, v := range g.status {
		gg.status[k] = v
	}
	return gg
}

// CloneReachable clones an escape graph, but only preserving the nodes that are reachable from roots.
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
		for d := range g.edges[n] {
			if !reachable[d] {
				reachable[d] = true
				worklist = append(worklist, d)
			}
		}
	}
	gg := NewEmptyEscapeGraph(g.nodes)
	for src, outEdges := range g.edges {
		if !reachable[src] {
			continue
		}
		newOutEdges := make(map[*Node]edgeFlags, len(outEdges))
		for dest, f := range outEdges {
			newOutEdges[dest] = f
		}
		gg.edges[src] = newOutEdges
	}
	for node, st := range g.status {
		if reachable[node] {
			gg.status[node] = st
		}
	}
	return gg
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
//
//gocyclo:ignore
func (g *EscapeGraph) Edges(src, dest *Node, includeExternal, includeInternal bool) []*Edge {
	edges := make([]*Edge, 0, 1)
	if src != nil {
		for d, es := range g.edges[src] {
			if dest == nil || dest == d {
				if includeExternal && (es&EdgeExternal != 0) {
					edges = append(edges, &Edge{src, d, false})
				}
				if includeInternal && (es&EdgeInternal != 0) {
					edges = append(edges, &Edge{src, d, true})
				}
			}
		}
	} else {
		for s, outEdges := range g.edges {
			for d, es := range outEdges {
				if dest == nil || dest == d {
					if includeExternal && (es&EdgeExternal != 0) {
						edges = append(edges, &Edge{s, d, false})
					}
					if includeInternal && (es&EdgeInternal != 0) {
						edges = append(edges, &Edge{s, d, true})
					}
				}
			}
		}
	}
	return edges
}

// Pointees returns the set of nodes (as a map to empty struct) that are pointed to by src by any
// type of direct edge.
func (g *EscapeGraph) Pointees(src *Node) map[*Node]struct{} {
	pointees := make(map[*Node]struct{}, 4)
	for d := range g.edges[src] {
		pointees[d] = struct{}{}
	}
	return pointees
}

// Deref() is required because globals are not represented in a uniform way with
// parameters/locals/freevars. In the SSA form, a global is implicitly a pointer to the its type. So
// if we have a global decl:
//
//	var global *S
//
// then in the SSA, the global name effectively has type **S. We can see this in that the operation
// global = &S{} turns into `t0 = alloc S; *global = t0`. The current graph representation makes the
// global node directly the node that stores the value, rather than pointing at a virtual node that
// then points at the actual value like a **S parameter would. This decision was made so that
// globals could be instantiated lazily via the NodeGroup: they don't need to create two nodes with
// an edge like params/freevars do. This is probably the wrong choice; instead, these node pairs
// should be created based on a scan of the instructions for globals that are accessed, during the
// creation of the initial escape graph.
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

// DerefEdges produces a slice of edges that are out-edges from a given node. It takes
// into account the oddness of the global variable representation.
func (g *EscapeGraph) DerefEdges(addr *Node) []*Edge {
	if addr == nil {
		return []*Edge{}
	}
	if addr.kind == KindGlobal {
		return []*Edge{{addr, addr, false}}
	}
	return g.Edges(addr, nil, true, true)
}

// Graphviz returns a (multi-line) dot/graphviz input describing the graph.
//
//gocyclo:ignore
func (g *EscapeGraph) Graphviz() string {
	out := bytes.NewBuffer([]byte{})
	fmt.Fprintf(out, "\ndigraph { // start of digraph\nrankdir = LR;\n")
	fmt.Fprintf(out, "graph[label=\"%s\"];\n", "")
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
			if t, ok := g.nodes.globalNodes.types[v]; ok {
				typeName := t.String()
				escaped := strings.ReplaceAll(strings.ReplaceAll(typeName, "\\", "\\\\"), "\"", "\\\"")
				extra = fmt.Sprintf("%s tooltip=\"%s\"", extra, escaped)
			} else {
				extra = extra + " color=red"
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
			if t, ok := g.nodes.globalNodes.types[v]; ok {
				typeName := t.String()
				escaped := strings.ReplaceAll(strings.ReplaceAll(typeName, "\\", "\\\\"), "\"", "\\\"")
				extra = fmt.Sprintf("%s tooltip=\"%s\"", extra, escaped)
			} else {
				extra = extra + " color=red"
			}
			escaped := strings.ReplaceAll(strings.ReplaceAll(v.debugInfo, "\\", "\\\\"), "\"", "\\\"")
			fmt.Fprintf(out, "%d [label=\"%s\" %s];\n", v.number, escaped, extra)
		}
		for _, e := range g.Edges(v, nil, true, true) {
			extra := "" // fmt.Sprintf("headlabel=\"%s\" taillabel=\"%s\"", e.destField, e.srcField)
			if !e.isInternal {
				extra += " style=dashed penwidth=2"
			}
			if g.nodes.globalNodes.parent[e.dest] == e.src {
				extra += " color=gray"
			}
			fmt.Fprintf(out, "%d -> %d [%s];\n", e.src.number, e.dest.number, extra)
		}
	}

	fmt.Fprintf(out, "} // end of digraph\n")
	return out.String()
}

// AddEdge adds an edge from base to dest. isInternal (usually `true`) signals whether
// this is an internal edge (created during the current function) or external edge
// (possibly existed before the current function).
func (g *EscapeGraph) AddEdge(src *Node, dest *Node, isInternal bool) (changed bool) {
	outEdges, ok := g.edges[src]
	if !ok {
		g.AddNode(src)
		outEdges = make(map[*Node]edgeFlags)
		g.edges[src] = outEdges
	}
	g.AddNode(dest)
	if isInternal {
		outEdges[dest] |= EdgeInternal
	} else {
		outEdges[dest] |= EdgeExternal
	}
	g.computeEdgeClosure(src, dest)
	return true
}

// AddNode ensures g has an entry for node n.
func (g *EscapeGraph) AddNode(n *Node) (changed bool) {
	if _, ok := g.status[n]; !ok {
		g.edges[n] = map[*Node]edgeFlags{}
		g.status[n] = n.IntrinsicEscape()
		return true
	}
	return false
}

// Subnodes have a "reason" for the subnode relationship. This struct
// represents the field subnode relationship, which is used for both struct
// fields and also field-like things such as keys[*] and values[*] of maps
type fieldSubnodeReason struct {
	field string
}

// FieldSubnode returns the singular field subnode of `base`, with label `field`.
// The type tp is a hint for the type to apply to the new node.
func (g *EscapeGraph) FieldSubnode(base *Node, field string, tp types.Type) *Node {
	if subnodes, ok := g.nodes.globalNodes.subnodes[base]; ok {
		if nodeData, ok := subnodes[fieldSubnodeReason{field}]; ok {
			g.AddEdge(base, nodeData.node, true)
			return nodeData.node
		}
		f := g.nodes.NewNode(base.kind, field, tp)
		subnodes[fieldSubnodeReason{field}] = struct {
			node *Node
			data any
		}{f, tp}
		g.nodes.globalNodes.parent[f] = base
		g.AddEdge(base, f, true)
		return f
	}
	f := g.nodes.NewNode(base.kind, field, tp)
	g.nodes.globalNodes.subnodes[base] = map[any]nodeWithData{fieldSubnodeReason{field}: {f, tp}}
	g.nodes.globalNodes.parent[f] = base
	g.AddEdge(base, f, true)
	return f
}

// IsSubnodeEdge returns whether base and n have a subnode relationship, from base to n.
// There may also be other edges between these two nodes.
func (g *EscapeGraph) IsSubnodeEdge(base, n *Node) bool {
	p, ok := g.nodes.globalNodes.parent[n]
	return ok && p == base
}

// IsSubnode returns true if n is a subnode of some other node.
func (g *EscapeGraph) IsSubnode(n *Node) bool {
	_, ok := g.nodes.globalNodes.parent[n]
	return ok
}

// AnalogousSubnode returns the subnode of base that has the same relationship with base that
// subnode has with its parent. Typically used to copy fields
func (g *EscapeGraph) AnalogousSubnode(base *Node, subnode *Node) *Node {
	// TODO make this work for all reasons, not just fields
	for reason, nodeData := range g.nodes.globalNodes.subnodes[g.nodes.globalNodes.parent[subnode]] {
		if r, ok := reason.(fieldSubnodeReason); ok && nodeData.node == subnode {
			return g.FieldSubnode(base, r.field, nodeData.data.(types.Type))
		}
	}
	panic("Subnode argument is not a subnode: reason not found")
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

// MergeNodeStatus sets the status of n to at least s. Doesn't modify the status if the current
// status is greater equal to s. Modifies g.
func (g *EscapeGraph) MergeNodeStatus(n *Node, s EscapeStatus) {
	if s > g.status[n] {
		g.status[n] = s
	} else {
		return
	}
	for pointee := range g.Pointees(n) {
		g.computeEdgeClosure(n, pointee)
	}
}

// WeakAssign applies the weak-assignment operation `dest = src`. Basically, ensures that dest
// points to whatever src points to. Weak here means that it does not erase any existing edges from
// dest. Handles subnodes recursively, so it works for structure types, but does not generate load
// nodes. See copyStruct.
func (g *EscapeGraph) WeakAssign(dest *Node, src *Node) {
	g.AddNode(dest)
	for _, e := range g.DerefEdges(src) {
		if g.IsSubnodeEdge(e.src, e.dest) {
			destNode := g.AnalogousSubnode(dest, e.dest)
			g.WeakAssign(destNode, e.dest)
		} else {
			g.AddEdge(dest, e.dest, e.isInternal)
		}
	}
}

// LoadField applies the load operation `valNode = *addrNode[.field]` and modifies g.
// This is a generalized operation: it also applies to reading the specified field from slices, maps, globals, etc.
// If field is empty (""), then dereference the object itself, otherwise dereference only the specified field.
// generateLoadNode is called to lazily create a node if the load can happen against an
// external object; this can't always be determined a priori, and we don't want to create a load node
// unless necessary.
func (g *EscapeGraph) LoadField(valNode *Node, addrNode *Node, generateLoadNode func() *Node, field string, tp types.Type) {
	var loadNode *Node
	// Nodes are addr ->* addrPointee ->* doublePointee
	// val = *addr means we need to add edges from val to whatever node(s) *addr (i.e. all the addrPointees)'
	// points to. The addrPointees are the nodes that addr points to, and the doublePointees are collectively
	// everything that *addr points to. Thus we need to collect all double pointees and add edges
	// from val to these nodes.
	for _, addrEdge := range g.DerefEdges(addrNode) {
		addrPointee := addrEdge.dest
		g.AddNode(addrPointee)
		addrPointeeField := addrPointee
		// For non-empty fields, we take edges from the field subnode of each pointee. Otherwise, we are treating
		// the pointee itself as a pointer-like object, and taking edges from that.
		if field != "" {
			addrPointeeField = g.FieldSubnode(addrPointee, field, tp)
		}
		// This is not .Deref(addrPointee) because the global is no longer being treated as an implicit pointer
		// in the ssa representation. Now, global nodes are treated the same as any other memory node, such as
		// structs, maps, etc.
		for _, pointeeEdge := range g.Edges(addrPointeeField, nil, true, true) {
			g.AddEdge(valNode, pointeeEdge.dest, true)
		}
		// if addrPointee is an escaped node, we need to add the load node
		if g.status[addrPointee] > Local {
			if loadNode == nil {
				loadNode = generateLoadNode()
			}
			g.AddEdge(valNode, loadNode, true)
			g.AddEdge(addrPointeeField, loadNode, false)
		}
	}
	// TODO: for load operations, if the pointer node itself (not just its pointee) is external then we have a
	// problem, as it will also need a load node. This may not occur depending on how the SSA is constructed, i.e.
	// if we only have e.g. instrType.X represented by a local variable (which will never be external).
}

// StoreField applies the effect of storing the pointer-like value valNode into the field of object(s) pointed to by addrNode. Generalizes
// to include map updates (m[k] = v), channel sends, and other operations that need to write to a specific "field" of the pointees of addr.
// If the field is empty (""), writes to the object itself.
func (g *EscapeGraph) StoreField(addrNode, valNode *Node, field string, tp types.Type) {
	// Store the value into all the possible aliases of *addr
	for _, edge := range g.DerefEdges(addrNode) {
		addrPointee := edge.dest
		for _, valEdge := range g.Edges(valNode, nil, true, true) {
			fieldNode := addrPointee
			if field != "" {
				fieldNode = g.FieldSubnode(addrPointee, field, tp)
			}
			g.AddEdge(fieldNode, valEdge.dest, true)
		}
	}
}

// Merge computes the union of this graph with another, used at e.g. the join-points of a dataflow graph. Modifies g in-place.
func (g *EscapeGraph) Merge(h *EscapeGraph) {
	for _, e := range h.Edges(nil, nil, true, true) {
		g.AddEdge(e.src, e.dest, e.isInternal)
	}
	for node, s := range h.status {
		g.MergeNodeStatus(node, s)
	}
}

// Call computes the result of splicing in the summary (callee) of the callee's graph. args are the
// nodes corresponding to the caller's actual parameters at the callsite (nil if not pointer-like).
// rets are the nodes corresponding to the caller values to assign the results to (nil if not
// pointer-like). callee is the summary of the called function.
//
//gocyclo:ignore
func (g *EscapeGraph) Call(args []*Node, freeVarsPointees [][]*Node, rets []*Node, callee *EscapeGraph) {
	pre := g.Clone()
	// u maps nodes in summary to the nodes in the caller
	u := map[*Node]map[Edge]struct{}{}
	// deferredReps are used to ensure one of the rules triggers consistently
	deferredReps := map[*Node]map[Edge]struct{}{}

	worklist := []Edge{}
	addUEdge := func(x, y *Node) {
		e := Edge{x, y, true}
		if m, ok := u[x]; ok {
			if _, ok := m[e]; ok {
				return
			}
			m[e] = struct{}{}
		} else {
			u[x] = map[Edge]struct{}{e: {}}
		}
		worklist = append(worklist, e)
	}
	addDeferredRep := func(x *Node, e Edge) {
		if m, ok := deferredReps[x]; ok {
			m[e] = struct{}{}
		} else {
			deferredReps[x] = map[Edge]struct{}{e: {}}
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
			addUEdge(formal, args[i])
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
			addUEdge(callee.nodes.ReturnNode(i, nil), ret)
		}
	}

	// Process edges in worklist
	for len(worklist) > 0 {
		edgeToProcess := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		base, rep := edgeToProcess.src, edgeToProcess.dest // base is in callee, rep is in g

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
					// 	addUEdge(baseEdge.dest, repEdge.dest)
					// }
					// Instead, we break the abstraction a bit and access the map directly
					for v := range pre.edges[rep] {
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
		// If the right u edge is added first, then when we process base/rep, we will
		// add the right thing. But if the left edge is added first, then we will miss adding
		// an edge as there will be no u edges from y -> x. Therefore, we add a "deferredRep"
		// edge from y to rep. If y -> x is ever added later, then the case below will trigger
		// and the edge will be completed.
		for _, edge := range callee.Edges(base, nil, false, true) {
			if callee.IsSubnodeEdge(edge.src, edge.dest) {
				// This is a special subnode edge, add the analogous edge in the caller graph, and link
				fieldNode := g.AnalogousSubnode(rep, edge.dest)
				addUEdge(edge.dest, fieldNode)
			} else {
				// Normal edge, y is edge.dest
				for uEdge := range u[edge.dest] {
					g.AddEdge(rep, uEdge.dest, true)
				}
				// Edge.dest will be overwritten by whatever x ends up being, so leave it nil.
				addDeferredRep(edge.dest, Edge{rep, nil, true})
			}

		}

		// Add edges for the pointees of parameters, to link them with their representatives in the caller.
		// This happens here so that we can handle subnodes appropriately. Subnodes still have the kind of their
		// parent, so e.g. fields of a paramter are still KindParamVar.
		if base.kind == KindParamVar {
			for _, edge := range callee.Edges(base, nil, true, true) {
				if callee.IsSubnodeEdge(edge.src, edge.dest) {
					// This is a special subnode edge
					// find the subnode relationship
					fieldNode := g.AnalogousSubnode(rep, edge.dest)
					addUEdge(edge.dest, fieldNode)
				} else {
					for p := range pre.Pointees(rep) {
						if !pre.IsSubnodeEdge(rep, p) {
							addUEdge(edge.dest, p)
						}
					}
				}

			}
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
		// We must keep track of what b was for field sensitivity.
		for e := range deferredReps[base] {
			g.AddEdge(e.src, rep, true)
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
			isInternalToAllocNode := edge.isInternal && (edge.dest.kind == KindAlloc || edge.dest.kind == KindUnknown)
			isLeakedLoadNode := edge.isInternal && (callee.status[edge.dest] == Leaked && edge.dest.kind == KindLoad)

			if isInternalToAllocNode || isLeakedLoadNode {
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

		if status, ok := pre.status[rep]; (!ok && g.status[rep] != Local) || status != Local {
			for _, edge := range callee.Edges(base, nil, true, true) {
				if !edge.isInternal || base.kind == KindGlobal {
					g.AddNode(edge.dest)
					g.nodes.AddForeignNode(edge.dest)

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
				g.MergeNodeStatus(rep, Leaked)
			}
		}
	}
}

// CallUnknown computes the result of calling an unknown function. An unknown function has no bound
// on its allowed semantics. This means that the arguments are assumed to leak, and the return value
// is treated similarly to a load node, except it can never be resolved with arguments like loads
// can be.
func (g *EscapeGraph) CallUnknown(args []*Node, rets []*Node) {
	for _, arg := range args {
		for n := range g.Pointees(arg) {
			g.MergeNodeStatus(n, Leaked)
		}
	}
	for _, ret := range rets {
		g.AddEdge(ret, g.nodes.UnknownReturnNode(), true)
	}
}

// Matches checks if two graphs are equal. Used for convergence checking.
func (g *EscapeGraph) Matches(h *EscapeGraph) bool {
	// TODO: This may become a performance bottleneck
	if !reflect.DeepEqual(g.status, h.status) {
		return false
	}
	if !reflect.DeepEqual(g.edges, h.edges) {
		return false
	}
	return true
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

// We use nodeWithData to allow associating extra data with a subnode relationship, without
// making it part of the lookup key. This is useful for field types, which may not be exactly
// the same in multiple uses (e.g. due to aliases).
type nodeWithData struct {
	node *Node
	data any
}

type globalNodeGroup struct {
	nextNode int
	function map[*Node]*ssa.Function
	subnodes map[*Node]map[any]nodeWithData // map from root node to reasons to subnode children
	parent   map[*Node]*Node                // nodes can only have one parent for now; subnodes form a forest.
	types    map[*Node]types.Type
	// TODO: introduce a mutex around nextNode for multithreading
}

func newGlobalNodeGroup() *globalNodeGroup {
	return &globalNodeGroup{0,
		make(map[*Node]*ssa.Function),
		make(map[*Node]map[any]nodeWithData),
		make(map[*Node]*Node),
		make(map[*Node]types.Type)}
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
	loads         map[any]*Node
	globals       map[ssa.Value]*Node
	foreign       map[*Node]struct{}
	params        map[ssa.Value]*Node
	tempNodes     map[any]*Node
	formals       []*Node
	freevars      []*Node
	returnNodes   map[int]*Node
	nilNode       *Node
	unusedNode    *Node
	unknownReturn *Node
	globalNodes   *globalNodeGroup
}

// NewNodeGroup returns a fresh node group that is tied to the underlying global group.
// Node groups with the same global node group may interact by sharing foreign nodes, but
// interactions across globalNodeGroups leads to unspecified behavior.
func NewNodeGroup(globalNodes *globalNodeGroup) *NodeGroup {
	return &NodeGroup{
		make(map[ssa.Value]*Node),
		make(map[ssa.Instruction]*Node),
		make(map[any]*Node),
		make(map[ssa.Value]*Node),
		make(map[*Node]struct{}),
		make(map[ssa.Value]*Node),
		make(map[any]*Node),
		make([]*Node, 0),
		make([]*Node, 0),
		make(map[int]*Node),
		nil,
		nil,
		nil,
		globalNodes,
	}
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
	g.globalNodes.types[node] = t
	return node
}

// ValueNode returns a node that represents a ssa.Value. Most such values are virtual registers created
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
	// Use variable type, unless it is a range (which doesn't have a type)
	if _, ok := variable.(*ssa.Range); !ok {
		g.globalNodes.types[node] = variable.Type()
	}
	return node
}

// NewNode returns an entirely new node with the defined fields, and the given type hint
func (g *NodeGroup) NewNode(kind NodeKind, debug string, tp types.Type) *Node {
	node := &Node{kind, g.globalNodes.getNewID(), debug}
	g.globalNodes.types[node] = tp
	return node
}

// ReturnNode returns the indexed return node of a function, which represents all the
// implicit or explicit variables that capture the returned values. There is
// one node per function return slot.
func (g *NodeGroup) ReturnNode(i int, t types.Type) *Node {
	if node, ok := g.returnNodes[i]; ok {
		if t != nil && g.globalNodes.types[node] == nil {
			g.globalNodes.types[node] = t
		}
		return node
	}

	node := &Node{KindReturn, g.globalNodes.getNewID(), fmt.Sprintf("return %v", i)}
	g.returnNodes[i] = node
	if t != nil && g.globalNodes.types[node] == nil {
		g.globalNodes.types[node] = t
	}
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
func (g *NodeGroup) LoadNode(location any, instr ssa.Instruction, t types.Type) *Node {
	node, ok := g.loads[location]
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
	g.loads[location] = node
	g.globalNodes.types[node] = t
	return node
}

// ParamNode creates a node for the initial pointee of a parameter/freevar. This is different from the var node of the pointer,
// which exists for consistency with SSA values
func (g *NodeGroup) ParamNode(param ssa.Value) *Node {
	node, ok := g.params[param]
	if ok {
		return node
	}
	var qualifier types.Qualifier
	if param.Parent().Package() != nil {
		qualifier = types.RelativeTo(param.Parent().Package().Pkg)
	}
	shortTypeName := types.TypeString(NillableDerefType(param.Type()), qualifier)
	node = &Node{KindParam, g.globalNodes.getNewID(), fmt.Sprintf("*%s %v", param.Name(), shortTypeName)}
	g.params[param] = node
	g.globalNodes.types[node] = NillableDerefType(param.Type())
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
