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
	"strings"

	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/lang"
	"github.com/awslabs/argot/internal/graphutil"
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

type EscapeStatus uint8

const (
	Local   EscapeStatus = 0
	Escaped              = 1
	Leaked               = 2
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
	edges  map[*Node]map[*Node]bool
	status map[*Node]EscapeStatus
	nodes  *NodeGroup
}

// Produces an empty graph, which is also the unit of Merge() below
func NewEmptyEscapeGraph(nodes *NodeGroup) *EscapeGraph {
	gg := &EscapeGraph{
		make(map[*Node]map[*Node]bool),
		make(map[*Node]EscapeStatus),
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
	for k, v := range g.status {
		gg.status[k] = v
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
			return true // changed: upgraded edge, but edge existed before so we don't need closure
		}
		// no edge of any kind between existing nodes
		m[dest] = isInternal
	} else {
		g.edges[base] = map[*Node]bool{dest: isInternal}
		g.status[base] = base.IntrinsicEscape()
	}
	// We added a new
	g.computeEdgeClosure(base, dest)
	return true
}

// Ensures g has an entry for n.
// This is necessary to ensure that EscapeClosure() knows about n, as it
// does not have access to the relevant NodeGroup.
func (g *EscapeGraph) AddNode(n *Node) (changed bool) {
	if _, ok := g.edges[n]; !ok {
		g.edges[n] = map[*Node]bool{}
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
		for succ := range g.edges[node] {
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
	for n := range g.edges[a] {
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
		// This is not .Deref(addrPointee) because the global is no longer being treated as an implicit pointer
		// in the ssa representation. Now, global nodes are treated the same as any other memory node, such as
		// structs, maps, etc.
		for doublePointee := range g.edges[addrPointee] {
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

// (Re)-computes the transitive closure of the leaked and escaped properties.
// This shouldn't be necessary to call manually unless you are using addEdgeNoClosure
// func (g *EscapeGraph) computeTransitiveClosure() {
// Compute leaked first, as escape depends on it
// g.computeTransitiveClosureForLeaked()
// g.computeTransitiveClosureForEscape()
// }

// Computes the reachability-based closure of escape over the edges of the graph.
// The roots are the nodes that are .IsIntrinsicallyExternal() or leaked. Then, if
// A has escaped, and there's an edge from A to B, then B has escaped too.
// func (g *EscapeGraph) computeTransitiveClosureForEscape() {
// 	worklist := []*Node{}
// 	for node := range g.edges {
// 		if node.IsIntrinsicallyExternal() || g.escaped[node] || g.leaked[node] {
// 			g.escaped[node] = true
// 			worklist = append(worklist, node)
// 		}
// 	}
// 	for len(worklist) > 0 {
// 		node := worklist[len(worklist)-1]
// 		worklist = worklist[:len(worklist)-1]
// 		for succ := range g.edges[node] {
// 			if !g.escaped[succ] {
// 				g.escaped[succ] = true
// 				worklist = append(worklist, succ)
// 			}
// 		}
// 	}
// }

// This is the same as computing closure for escaped, but for leaked. The difference
// is that in general fewer things will be leaked than escaped. Because leak implies
// escaped, this should be called before closure for escaped, so that it can propagate
// properly.
// func (g *EscapeGraph) computeTransitiveClosureForLeaked() {
// 	worklist := []*Node{}
// 	for node := range g.edges {
// 		if node.IsIntrinsicallyLeaked() || g.leaked[node] {
// 			g.leaked[node] = true
// 			worklist = append(worklist, node)
// 		}
// 	}
// 	for len(worklist) > 0 {
// 		node := worklist[len(worklist)-1]
// 		worklist = worklist[:len(worklist)-1]
// 		for succ := range g.edges[node] {
// 			if !g.leaked[succ] {
// 				g.leaked[succ] = true
// 				worklist = append(worklist, succ)
// 			}
// 		}
// 	}
// }

// Computes the union of this graph with another, used at e.g. the join-points of a dataflow graph.
// Modifies g in-place.
func (g *EscapeGraph) Merge(h *EscapeGraph) {
	for node, edges := range h.edges {
		g.AddNode(node)
		g.JoinNodeStatus(node, h.status[node])
		for dest, isInternal := range edges {
			g.AddEdge(node, dest, isInternal)
		}
	}
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
		if formal != nil {
			addUEdge(formal, args[i])
		}
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
		// Adds node load to g, and adds the mapping edge u' and edge rep - -> load'
		// rep  - - -> load'
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
				if pre.status[rep] == Local {
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
			if callee.status[base] == Leaked {
				for rep := range repNodes {
					if g.status[rep] < Leaked {
						changed = true
						g.JoinNodeStatus(rep, Leaked)
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

// Computes the result of splicing in the summary (callee) of the callee's graph.
// args are the nodes corresponding to the caller's actual parameters at the callsite (nil if not pointer-like)
// rets are the nodes corresponding to the caller values to assign the results to (nil if not pointer-like)
// nodes is the NodeGroup for the caller, and also therefore the graph g
// summary is the summary of the called function.
// summaryNodes is the nodeGroup in the context of the called function
func (g *EscapeGraph) CallFast(args []*Node, rets []*Node, callee *EscapeGraph) {
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
			addUEdge(formal, args[i])
		}
	}
	for _, ret := range rets {
		if ret != nil {
			addUEdge(callee.nodes.ReturnNode(), ret)
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
			for load, isBaseLoadInternal := range callee.edges[base] {
				// Need base - - - > load to be an external edge (but also treat edges from param nodes as external)
				if !(isBaseLoadInternal && base.kind != KindParamVar) {
					for v, isRepVInternal := range pre.edges[rep] {
						if isRepVInternal {
							addUEdge(load, v)
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
		// If the right u edge is already present, then when we process base/rep, we will
		// add the right thing. But if the left edge is added first, then we will miss adding
		// an edge as there will be no edges from y -> x. Therefore, we add a "deferredRep"
		// edge from y to rep. If y -> x is ever added later, then the case below will trigger
		// and the edge
		for y, isBaseYInternal := range callee.edges[base] {
			// Need base -> y to be an internal edge (i.e. created during the execution of callee)
			if isBaseYInternal {
				for x := range u[y] {
					g.AddEdge(rep, x, true)
				}
				addDeferredRep(y, rep)
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
		// We do not keep track of what b was, but it must have existed.
		for r := range deferredReps[base] {
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
		for alloc, isBaseAllocInternal := range callee.edges[base] {
			if isBaseAllocInternal && (alloc.kind == KindAlloc || alloc.kind == KindUnknown) {
				g.nodes.AddForeignNode(alloc)
				g.AddNode(alloc)
				addUEdge(alloc, alloc)
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

		if pre.status[rep] != Local {
			for load, isBaseLoadInternal := range callee.edges[base] {
				if !isBaseLoadInternal {
					g.AddNode(load)
					g.nodes.AddForeignNode(load)
					g.AddEdge(rep, load, false)
					addUEdge(load, load)
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

// Computes the result of calling an unknown function.
// An unknown function has no bound on its allow semantics. This means that the
// arguments are assumed to leak, and the return value is treated similarly to a
// load node, except it can never be resolved with arguments like loads can be.
func (g *EscapeGraph) CallUnknown(args []*Node, rets []*Node) {
	for _, arg := range args {
		for n := range g.edges[arg] {
			g.JoinNodeStatus(n, Leaked)
		}
	}
	for _, ret := range rets {
		g.AddEdge(ret, g.nodes.UnknownReturnNode(), true)
	}
}

// Computes the result of calling an builtin. The name (len, copy, etc) and the
// effective type can be retrieved from the ssa.Builtin.
// An unknown function has no bound on its allow semantics. This means that the
// arguments are assumed to leak, and the return value is treated similarly to a
// load node, except it can never be resolved with arguments like loads can be.
func (g *EscapeGraph) CallBuiltin(instr ssa.Instruction, builtin *ssa.Builtin, args []*Node, rets []*Node) {
	switch builtin.Name() {
	case "len": // No-op, as does not leak and the return value is not pointer-like
		return
	case "cap": // No-op, as does not leak and the return value is not pointer-like
		return
	case "close": // No-op, as does not leak and the return value is not pointer-like
		return
	case "complex": // No-op, as does not leak and the return value is not pointer-like
		return
	case "real": // No-op, as does not leak and the return value is not pointer-like
		return
	case "imag": // No-op, as does not leak and the return value is not pointer-like
		return
	case "print": // No-op, as does not leak and no return value
		return
	case "println": // No-op, as does not leak and no return value
		return
	case "recover": // We don't track panic values, so treat like an unknown call
		g.CallUnknown(args, rets)
	case "ssa:wrapnilchk": // treat as identity fucntion
		g.WeakAssign(rets[0], args[0], nil)
	case "delete": // treat as noop, as we don't actually erase information
		return
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
		for baseArray := range g.edges[sliceArg] {
			for xArray := range g.edges[xArg] {
				g.WeakAssign(baseArray, xArray, sliceType.Elem())
			}
			// The return value can be one of the existing backing arrays
			g.AddEdge(ret, baseArray, true)
		}
		// Then, simulate an allocation. This happens second so we pick up the newly added edges
		allocArray := g.nodes.AllocNode(instr, types.NewArray(sliceType.Elem(), -1))
		for baseArray := range g.edges[sliceArg] {
			g.WeakAssign(allocArray, baseArray, sliceType.Elem())
		}
		g.AddEdge(ret, allocArray, true)
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
		for destArray := range g.edges[destArg] {
			for srcArray := range g.edges[srcArg] {
				g.WeakAssign(destArray, srcArray, sliceType.Elem())
			}
		}
	default:
		fmt.Printf("Unhandled: %v\n", builtin.Name())
	}
}

// Checks if two graphs are equal. Used for convergence checking.
func (g *EscapeGraph) Matches(h *EscapeGraph) bool {
	// TODO: This may become a performance bottleneck
	return reflect.DeepEqual(g.edges, h.edges) && reflect.DeepEqual(g.status, h.status)
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
		nil,
		nil,
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
	if nodes.returnNode != nil {
		add(nodes.returnNode)
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

// The nil node of a function, which represents a pointer that is always nil
// Invariant: should not have any out edges (i.e. should never be assigned to)
func (g *NodeGroup) NilNode() *Node {
	if g.nilNode != nil {
		return g.nilNode
	}
	node := &Node{KindVar, g.globalNodes.getNewID(), "nil"}
	g.nilNode = node
	return node
}

// The unused pointer node, which represents a node that you don't care about.
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

// Gives the type of hte contents
func ChannelContentsType(t types.Type) types.Type {
	switch tt := t.Underlying().(type) {
	case *types.Chan:
		return tt.Elem()
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
	case *ssa.MakeChan:
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
		// raw array is different than *array and slice
		if _, ok := instrType.X.Type().Underlying().(*types.Array); ok {
			// Array case. It is unclear how this is generated, and what the semantics should be in this case.
			panic("IndexAddr of direct array")
		} else {
			// *array or slice
			for varPointee := range g.Deref(nodes.ValueNode(instrType.X)) {
				g.AddEdge(nodes.ValueNode(instrType), varPointee, true)
			}
			return
		}
	case *ssa.Store:
		if lang.IsNillableType(instrType.Val.Type()) {
			g.Store(nodes.ValueNode(instrType.Addr), nodes.ValueNode(instrType.Val), instrType.Val.Type())
		}
		return
	case *ssa.UnOp:
		// Check if this is a load operation
		if _, ok := instrType.X.Type().(*types.Pointer); ok && instrType.Op == token.MUL {
			if lang.IsNillableType(instrType.Type()) {
				gen := func() *Node {
					return nodes.LoadNode(instr, PointerDerefType(instrType.X.Type().Underlying()))
				}
				g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
			}
			return
		} else if _, ok := instrType.X.Type().(*types.Chan); ok && instrType.Op == token.ARROW {
			// recv on channel
			if lang.IsNillableType(instrType.Type()) {
				gen := func() *Node {
					return nodes.LoadNode(instr, ChannelContentsType(instrType.X.Type().Underlying()))
				}
				g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
			}
			return
		} else {
			// arithmetic UnOp: no-op
			return
		}
	case *ssa.Send:
		if lang.IsNillableType(instrType.X.Type()) {
			// Send on channel is a write to the contents "field" of the channel
			g.Store(nodes.ValueNode(instrType.Chan), nodes.ValueNode(instrType.X), instrType.X.Type())
		}
		return
	case *ssa.Slice:
		switch tp := instrType.X.Type().Underlying().(type) {
		case *types.Slice:
			// Slice of slice, basic copy
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
			return
		case *types.Basic:
			if tp.Kind() != types.String && tp.Kind() != types.UntypedString {
				panic("Slice of BasicKind that isn't string: " + tp.String())
			}
			// Slice of a string creates a hidden allocation of an array to hold the string contents.
			g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, tp), true)
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
	case *ssa.Select:
		recvIndex := 0 // for tuple sensitivity, this will be the index that should be read in the result tuple.
		for _, st := range instrType.States {
			if st.Dir == types.RecvOnly {
				if lang.IsNillableType(ChannelContentsType(st.Chan.Type())) {
					// TODO: This should be one load node per branch, so that different types
					// get different nodes. This is only important if we are tuple sensitive and
					// make the graph typed. For now, the different cases can safe share nodes,
					// which is imprecise but sound.
					gen := func() *Node {
						return nodes.LoadNode(instr, ChannelContentsType(st.Chan.Type()))
					}
					g.Load(nodes.ValueNode(instrType), nodes.ValueNode(st.Chan), gen)
				}
				recvIndex += 1
			} else if st.Dir == types.SendOnly {
				if lang.IsNillableType(st.Send.Type()) {
					// Send on channel is a write to the contents "field" of the channel
					g.Store(nodes.ValueNode(st.Chan), nodes.ValueNode(st.Send), st.Send.Type())
				}
			} else {
				panic("Unexpected ")
			}
		}
		return
	case *ssa.Panic:
		g.CallUnknown([]*Node{nodes.ValueNode(instrType.X)}, []*Node{nodes.UnusedNode()})
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

		if builtin, ok := instrType.Call.Value.(*ssa.Builtin); ok {
			g.CallBuiltin(instrType, builtin, args, rets)
			return
		} else if callee := instrType.Call.StaticCallee(); callee != nil {
			summary := ea.prog.summaries[callee]
			if summary != nil {
				// We can use the finalGraph pointer freely as it will never change after it is created
				summary.summaryUses[summaryUse{ea, instrType}] = summary.finalGraph
				if verbose {
					fmt.Printf("Call at %v: %v %v %v\n", instr.Parent().Prog.Fset.Position(instr.Pos()), summary.function.String(), args, summary.finalGraph.nodes.formals)
				}
				g.CallFast(args, rets, summary.finalGraph)
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

	case *ssa.Go:
		args := make([]*Node, len(instrType.Call.Args))
		for i, arg := range instrType.Call.Args {
			if lang.IsNillableType(arg.Type()) {
				args[i] = nodes.ValueNode(arg)
			}
		}
		rets := []*Node{nodes.UnusedNode()}
		// A go call always leaks arguements. The return value is irrelevant (`_`).
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
		case *types.Array:
			if lang.IsNillableType(instrType.Type()) {
				g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
			}
			return
		}
	case *ssa.Lookup:
		if lang.IsNillableType(instrType.Type().Underlying()) {
			gen := func() *Node { return nodes.LoadNode(instr, instrType.Type()) }
			g.Load(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), gen)
		}
		return
	case *ssa.MapUpdate:
		if lang.IsNillableType(instrType.Value.Type()) {
			g.Store(nodes.ValueNode(instrType.Map), nodes.ValueNode(instrType.Value), instrType.Value.Type())
		}
		if lang.IsNillableType(instrType.Key.Type()) {
			g.Store(nodes.ValueNode(instrType.Map), nodes.ValueNode(instrType.Key), instrType.Key.Type())
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
		if lang.IsNillableType(instrType.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.X.Type())
		} else {
			g.AddNode(nodes.ValueNode(instrType)) // Make interface from string or other non-pointer type
		}
		return
	case *ssa.TypeAssert:
		if lang.IsNillableType(instrType.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
		}
		return
	case *ssa.Convert:
		if lang.IsNillableType(instrType.X.Type()) {
			g.WeakAssign(nodes.ValueNode(instrType), nodes.ValueNode(instrType.X), instrType.Type())
		} else if _, ok := instrType.Type().Underlying().(*types.Slice); ok {
			if basic, ok := instrType.X.Type().Underlying().(*types.Basic); ok && (basic.Kind() == types.String || basic.Kind() == types.UntypedString) {
				// We must be converting a string to a slice, so the semantics are to do a hidden allocation
				g.AddEdge(nodes.ValueNode(instrType), nodes.AllocNode(instrType, instrType.Type()), true)
			}
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
	if verbose || true {
		ea.prog.logger.Printf("At %v\n", instr.Parent().Prog.Fset.Position(instr.Pos()))
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
		verbose:     state.Config.Verbose,
		globalNodes: &globalNodeGroup{0},
		logger:      state.Logger,
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
	if prog.verbose {
		prog.logger.Printf("Have a total of %d nodes", len(nodes))
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
	// The main worklist algorithm. Reanalyze each function, putting any function(s) that need to be reanalyzed back on the list
	for len(worklist) > 0 {
		summary := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		funcName := summary.function.Name()
		if prog.verbose {
			state.Logger.Printf("Analyzing %v\n", funcName)
		}
		changed := resummarize(summary)
		if prog.verbose {
			state.Logger.Printf("Func %s is (changed=%v):\n%s\n", funcName, changed, summary.finalGraph.GraphvizLabel(funcName))
		}
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
					state.Logger.Printf("Func %s summary is:\n%s\n", f.String(), summary.finalGraph.GraphvizLabel(f.String()))
				}
			}
		}
	}
	return prog, nil
}

// Returns true if all of the nodes pointed to by `ptr` are local, i.e.
// not escaped or leaked. Ignores the status of `ptr` itself.
func derefsAreLocal(g *EscapeGraph, ptr *Node) bool {
	for n := range g.Deref(ptr) {
		if g.status[n] != Local {
			return false
		}
	}
	return true
}

// Returns true if the given instruction is local w.r.t. the given escape graph.
func instructionLocality(instr ssa.Instruction, g *EscapeGraph) bool {
	switch instrType := instr.(type) {
	case *ssa.Store:
		return derefsAreLocal(g, g.nodes.ValueNode(instrType.Addr))
	case *ssa.UnOp:
		if _, ok := instrType.X.Type().(*types.Pointer); ok && instrType.Op == token.MUL {
			// Load Op
			return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
		} else if _, ok := instrType.X.Type().(*types.Chan); ok && instrType.Op == token.ARROW {
			// recv on channel
			return derefsAreLocal(g, g.nodes.ValueNode(instrType.X))
		} else {
			// arithmetic is local
			return true
		}
	case *ssa.MakeClosure:
		// TODO: is this just return true?
		// fallthrough for now
	case *ssa.Alloc, *ssa.MakeMap, *ssa.MakeChan, *ssa.MakeSlice:
		return true
	case *ssa.FieldAddr, *ssa.IndexAddr:
		// address calculations don't involve loads
		// TODO: what about ssa.IndexAddr with arrays?
		return true

	case *ssa.MakeInterface, *ssa.TypeAssert, *ssa.Convert, *ssa.ChangeInterface, *ssa.ChangeType, *ssa.Phi, *ssa.Extract:
		// conversions and ssa specific things don't access memory
		return true
	case *ssa.Return, *ssa.Jump, *ssa.If:
		// control flow (at least the operation itself, if not the computation of the argument(s)) is local
		return true
	default:
		// fallthrough to the unhandled case below.
		// Some operation can fallthrough as well, because they might not (yet) handle all forms of their instruction type.
	}
	fmt.Printf("Warning, unhandled locality for instruction %v\n", instr)
	return false
}

// Fills in the locality map with the locality information of the instructions in the given basic block.
func basicBlockInstructionLocality(ea *functionAnalysisState, bb *ssa.BasicBlock, locality map[ssa.Instruction]bool) error {
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
		locality[instr] = instructionLocality(instr, g)
		ea.transferFunction(instr, g, false)
	}
	return nil
}

// Does the work of computing instruction locality for a function. See wrapper `ComputeInstructionLocality`.
func computeInstructionLocality(ea *functionAnalysisState, initial *EscapeGraph) map[ssa.Instruction]bool {
	inContextEA := &functionAnalysisState{
		function:     ea.function,
		prog:         ea.prog,
		initialGraph: initial,
		nodes:        ea.nodes,
		blockEnd:     make(map[*ssa.BasicBlock]*EscapeGraph),
		worklist:     []*ssa.BasicBlock{ea.function.Blocks[0]},
	}
	resummarize(inContextEA)
	locality := map[ssa.Instruction]bool{}
	for _, block := range ea.function.Blocks {
		basicBlockInstructionLocality(inContextEA, block, locality)
	}
	return locality
}

// Compute the instruction locality for all instructions in f, assuming it is called from one of the callsites
// Callsite should contain the escape graph from f's perspective; such graphs can be generated using ComputeCallsiteGraph,
// Merge, and ComputeArbitraryCallerGraph as necessary.
// In the returned map, a `true` value means the instruction is local, i.e. only manipulates memory that is proven to be local
// to the current goroutine. A `false` value means the instruction may read or write to memory cells that may be shared.
func ComputeInstructionLocality(f *ssa.Function, prog *ProgramAnalysisState, context *EscapeGraph) map[ssa.Instruction]bool {
	return computeInstructionLocality(prog.summaries[f], context)
}

// Computes the callsite graph from the perspective of `callee`, from the instruction `call` in `caller` when `caller` is called with `callerContext`.
// A particular call instruction can have multiple callee functions; a possible `g` must be supplied.
func ComputeCallsiteGraph(callerContext *EscapeGraph, caller *ssa.Function, call *ssa.Call, prog *ProgramAnalysisState, callee *ssa.Function) *EscapeGraph {
	panic("unimplemented")
	return ComputeArbitraryCallerGraph(callee, prog)
	// TODO: actually compute this
	// Step 1: Run the normal convergence loop with the given context escape graph.
	// Step 2: read off the escape graph at the point just before the call
	// Step 3: Translate from caller to callee's context (rename from arguments to formal parameters).
}

// Computes the caller graph for a function, making no assumptions about the caller. This is useful if a function
// has no known caller or it can't be precisely determined. Use of this function may result in significantly fewer
// "local" values than using precise information from ComputeCallsiteGraph.
// (This graph is actually already computed; this function merely copies it.)
func ComputeArbitraryCallerGraph(f *ssa.Function, prog *ProgramAnalysisState) *EscapeGraph {
	return prog.summaries[f].initialGraph.Clone()
}
