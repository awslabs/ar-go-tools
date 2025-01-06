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

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

// Effectively an enum of the types of node.
type nodeKind int

const (
	// KindAlloc cells of allocations that happen locally
	KindAlloc nodeKind = iota
	// KindParam Pointees of initial pointer-like parameters
	KindParam
	// KindLoad Represent the object loaded from a pointer/field of an external object
	KindLoad
	// KindGlobal The memory location of a global/package level variable (pointee of ssa.Global)
	KindGlobal
	// KindGlobalVar Pointer to the location of a heap object (represents the ssa.Global itself)
	KindGlobalVar
	// KindVar A local variable, i.e. SSA var
	KindVar
	// KindParamVar A parameter variable (both formals and free variables/method receiver)
	KindParamVar
	// KindReturn The return value of the current function
	KindReturn
	// KindUnknown A return value from an unanalyzed method without a summary
	KindUnknown
)

// EscapeStatus represents whether a node is Local, Escaped, or Leaked
type EscapeStatus uint8

const (
	// Local status indicates the value has not escaped
	Local EscapeStatus = 0
	// Escaped status indicates the value has escaped
	Escaped EscapeStatus = 1
	// Leaked status indicates the value has leaked
	Leaked EscapeStatus = 2
)

// edgeFlags are used when representing an edge, as we can pack multiple edges into the same byte
type edgeFlags uint8

const (
	// EdgeInternal flags internal edges
	EdgeInternal edgeFlags = 1 << iota
	// EdgeExternal flags external edges
	EdgeExternal
	// EdgeSubnode flags subnodes
	EdgeSubnode
	// EdgeAll is the conjunction of all types of edges
	EdgeAll = EdgeInternal | EdgeExternal | EdgeSubnode
)

// A Node represents the objects tracked by the escape analysis. Nodes represent local variables,
// globals, parameters, and heap cells of various kinds (maps, slices, arrays, structs)
type Node struct {
	kind      nodeKind
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

// EscapeGraph is the element of the monotone framework and the primary focus of the escape
// analysis. The graph represents edges as src -> dest -> isInternal. The final bool is semantically
// significant: the edges are labeled as internal or external. Escaped is a set of nodes that are
// not known to be local in the current context; they are treated differently on load operations.
// Leaked is a subset of escaped nodes that have (possibly) leaked out of the current goroutine,
// whereas escaped nodes may still be local depending on the calling context. The major operations
// on escape graphs are to AddEdge()s, (plus composite operations like Load, WeakAssign), Merge(),
// and compare with Matches().
type EscapeGraph struct {
	edges      map[*Node]map[*Node]edgeFlags
	status     map[*Node]EscapeStatus
	rationales map[*Node]*dataflow.EscapeRationale
	nodes      *NodeGroup
}

// Edge represents a single atomic edge within the escape graph. Nodes connected by more than one kind of
// edge will produce multiple Edge's when queried.
type Edge struct {
	src        *Node
	dest       *Node
	isInternal bool
	isSubnode  bool
	mask       edgeFlags
}

// NewEmptyEscapeGraph produces an empty graph, which is also the unit of Merge() below
func NewEmptyEscapeGraph(nodes *NodeGroup) *EscapeGraph {
	gg := &EscapeGraph{
		make(map[*Node]map[*Node]edgeFlags),
		make(map[*Node]EscapeStatus),
		make(map[*Node]*dataflow.EscapeRationale),
		nodes,
	}
	return gg
}

// Clone clones a graph, preserving node identities between the two graphs.
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
	for k, v := range g.rationales {
		gg.rationales[k] = v
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
	for node, st := range g.rationales {
		if reachable[node] {
			gg.rationales[node] = st
		}
	}
	return gg
}

// Edges (s, d, mask) finds all the edges from s to d that match the bitflags in mask.
// Either or s or d may be nil, in which case they act as a wild card. To find all the edges from
// src to all nodes via only internal edges, do:
//
//	g.Edges(src, nil, EdgeInternal).
//
// To iterate over the result, use a loop like:
//
//	for _, e := range g.Edges(src, nil, EdgeInternal) {
//	       fmt.Printf("Found %v", e.dest)
//	}
//
// If the mask is zero, the result will always be empty. This method is convenient, but may not be
// the most efficient.
//
//gocyclo:ignore
func (g *EscapeGraph) Edges(src, dest *Node, mask edgeFlags) []*Edge {
	edges := make([]*Edge, 0, 1)
	if src != nil {
		for d, es := range g.edges[src] {
			if dest == nil || dest == d {
				if es&mask == 0 {
					continue
				}
				if es&mask&EdgeExternal != 0 {
					edges = append(edges, &Edge{src, d, false, false, EdgeExternal})
				}
				if es&mask&EdgeInternal != 0 {
					edges = append(edges, &Edge{src, d, true, false, EdgeInternal})
				}
				if es&mask&EdgeSubnode != 0 {
					edges = append(edges, &Edge{src, d, true, true, EdgeSubnode})
				}
			}
		}
	} else {
		for s, outEdges := range g.edges {
			for d, es := range outEdges {
				if dest == nil || dest == d {
					if es&mask&EdgeExternal != 0 {
						edges = append(edges, &Edge{s, d, false, false, EdgeExternal})
					}
					if es&mask&EdgeInternal != 0 {
						edges = append(edges, &Edge{s, d, true, false, EdgeInternal})
					}
					if es&mask&EdgeSubnode != 0 {
						edges = append(edges, &Edge{s, d, true, true, EdgeSubnode})
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
	pointees := make(map[*Node]struct{})
	for d := range g.edges[src] {
		pointees[d] = struct{}{}
	}
	return pointees
}

// Graphviz returns a (multi-line string) dot/graphviz input describing the graph.
//
//gocyclo:ignore
func (g *EscapeGraph) Graphviz() string {
	out := bytes.NewBuffer([]byte{})
	fmt.Fprintf(out, "\n"+`digraph { // start of digraph
		rankdir = LR;
		compound=false;
		newrank=true;
		remincross=true;
		nodesep=0.1
		ranksep=0.5;
		`)
	fmt.Fprintf(out, "graph[label=\"%s\"];\n", "")

	ordered := []*Node{}
	for k := range g.status {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].number < ordered[j].number })

	isFieldParent := map[*Node]bool{}
	ordinaryAncestor := map[*Node]*Node{}
	for _, v := range ordered {
		subnodes := g.nodes.globalNodes.subnodes[v]
		if subnodes == nil {
			continue
		}
		for reason, nodeData := range subnodes {
			_, ok := reason.(fieldSubnodeReason)
			_, ok2 := reason.(implementationSubnodeReason)
			if ok || ok2 {
				isFieldParent[v] = true
				p := nodeData.node
				for g.IsSubnode(p) {
					p = g.nodes.globalNodes.parent[p].node
				}
				ordinaryAncestor[nodeData.node] = p
			}
		}
	}

	var subnodeLabel func(n *Node) string
	subnodeLabel = func(n *Node) string {
		extra := ""
		extraFont := ""
		escapedRationale := "none"
		if r, ok := g.rationales[n]; ok && r != nil {
			escapedRationale = r.String()
		}
		if t, ok := g.nodes.globalNodes.types[n]; ok {
			tooltip := fmt.Sprintf("%d tp %s esc: %s", n.number, t.String(), escapedRationale)
			escapedTooltip := strings.ReplaceAll(strings.ReplaceAll(tooltip, "\\", "\\\\"), "\"", "\\\"")
			extra = fmt.Sprintf("%s TOOLTIP=\"%s\" HREF=\"\"", extra, escapedTooltip)
		} else {
			extra = fmt.Sprintf("%s COLOR=\"#FF0000\" TOOLTIP=\"tp ? esc: %s\"", extra, escapedRationale)
		}
		t := fmt.Sprintf(`<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD ALIGN="left" %s><FONT %s>%s</FONT></TD></TR>`, extra, extraFont, n.debugInfo)

		// Walk over all field subnode children and render them
		type pair struct {
			reason string
			node   *Node
		}
		children := []pair{}
		for reason, nodeData := range g.nodes.globalNodes.subnodes[n] {
			if r, ok := reason.(fieldSubnodeReason); ok && g.edges[nodeData.node] != nil {
				children = append(children, pair{fmt.Sprintf("%v", r), nodeData.node})
			}
		}
		sort.Slice(children, func(i int, j int) bool { return children[i].reason < children[j].reason })
		for _, p := range children {
			child := p.node
			colorProp := ""
			if g.status[child] == Escaped {
				colorProp = " COLOR=\"#CCCCCC\""
			} else if g.status[child] == Leaked {
				colorProp = " COLOR=\"#555555\""
			}
			t += fmt.Sprintf(`<TR><TD BORDER="1"%s PORT="%d" ALIGN="left" CELLPADDING="4">%s</TD></TR>`,
				colorProp, child.number, subnodeLabel(child))

		}
		// Walk over all implementation subnode children and render them
		children = []pair{}
		for reason, nodeData := range g.nodes.globalNodes.subnodes[n] {
			if r, ok := reason.(implementationSubnodeReason); ok && g.edges[nodeData.node] != nil {
				children = append(children, pair{fmt.Sprintf("%v", r), nodeData.node})
			}
		}
		sort.Slice(children, func(i int, j int) bool { return children[i].reason < children[j].reason })
		for _, p := range children {
			child := p.node
			colorProp := ""
			if g.status[child] == Escaped {
				colorProp = " COLOR=\"#CCCCCC\""
			} else if g.status[child] == Leaked {
				colorProp = " COLOR=\"#555555\""
			}
			t += fmt.Sprintf(`<TR><TD BORDER="1"%s PORT="%d" ALIGN="left" CELLPADDING="4">%s</TD></TR>`,
				colorProp, child.number, subnodeLabel(child))

		}
		t += `</TABLE>`
		return t
	}
	var renderNode func(n *Node, root bool) = func(n *Node, root bool) {
		// Subnodes are rendered with their parent.
		// TODO: this should only be for field subnodes
		if g.IsSubnode(n) && root {
			return
		}
		extra := ""
		if _, ok := g.nodes.globalNodes.types[n]; !ok {
			extra += " color=red"
		}
		if n.kind == KindVar || n.kind == KindParamVar || n.kind == KindReturn {
			extra += " style=rounded width=0 height=0 margin=0.05 "
		}
		if g.status[n] == Escaped {
			extra += " style=dotted"
		}
		if g.status[n] == Leaked {
			extra += " style=dashed"
		}
		fmt.Fprintf(out, "%d [shape=rect %s label=<%s>];\n", n.number, extra, subnodeLabel(n))

	}

	// Write out the variables in a subgraph, so they show up on the left hand side
	fmt.Fprintf(out, "subgraph {\nrank=min;\n")
	prevInVarBlock := -1
	for _, n := range ordered {
		if n.kind == KindVar || n.kind == KindParamVar || n.kind == KindReturn {
			renderNode(n, true)
			// Add invisible edges to order the nodes, skipping subnodes
			if g.IsSubnode(n) {
				continue
			}
			if prevInVarBlock >= 0 {
				fmt.Fprintf(out, "%d -> %d [style=invis];\n", prevInVarBlock, n.number)
			}
			prevInVarBlock = n.number
		}
	}
	fmt.Fprintf(out, "} // subgraph\n")

	// Now add the rest of the nodes
	for _, n := range ordered {
		if !(n.kind == KindVar || n.kind == KindParamVar || n.kind == KindReturn) {
			renderNode(n, true)
		}
	}

	// Add all edges. Uses a helper function to generate the write port string
	nodePort := func(n *Node) string {
		if p, ok := ordinaryAncestor[n]; ok {
			return fmt.Sprintf("%d:%d", p.number, n.number)
		}
		return fmt.Sprintf("%d", n.number)
	}
	for _, n := range ordered {
		for _, e := range g.Edges(n, nil, EdgeInternal|EdgeExternal) {
			extra := ""
			if !e.isInternal {
				extra += " style=dashed"
			}
			fmt.Fprintf(out, "%s:e -> %s:w [%s];\n", nodePort(e.src), nodePort(e.dest), extra)
		}
		// Add a back-edge for load node parents, which is mostly useful for internal debugging purposes.
		if parent, ok := g.nodes.loadBase[n]; ok {
			fmt.Fprintf(out, "%s:w -> %s:e [%s];\n", nodePort(n), nodePort(parent), "color=orange constraint=false")
		}
	}

	fmt.Fprintf(out, "\n} // end of digraph\n")
	return out.String()
}

// AddEdge adds an edge from base to dest. isInternal (usually `true`) signals whether
// this is an internal edge (created during the current function) or external edge
// (possibly existed before the current function).
func (g *EscapeGraph) AddEdge(src *Node, dest *Node, newFlag edgeFlags) (changed bool) {
	outEdges, ok := g.edges[src]
	if !ok {
		g.AddNode(src)
		outEdges = make(map[*Node]edgeFlags)
		g.edges[src] = outEdges
	}
	g.AddNode(dest)
	outEdges[dest] |= newFlag
	g.computeEdgeClosure(src, dest)
	return true
}

// AddNode ensures g has an entry for node n.
func (g *EscapeGraph) AddNode(n *Node) (changed bool) {
	if _, ok := g.status[n]; !ok {
		g.edges[n] = map[*Node]edgeFlags{}
		status := n.IntrinsicEscape()
		g.status[n] = status
		if n.kind == KindGlobal {
			g.rationales[n] = dataflow.NewBaseRationale(fmt.Sprintf("global %s", n.debugInfo))
		}
		if n.kind == KindUnknown {
			g.rationales[n] = dataflow.NewBaseRationale(fmt.Sprintf("unknown node %s", n.debugInfo))
		}
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

// Subnodes have a "reason" for the subnode relationship. This struct represents the concrete
// implementation subnode relationship, which is used for interfaces and function pointers.
type implementationSubnodeReason struct {
	tp string
}

// FieldSubnode returns the singular field subnode of `base`, with label `field`.
// The type tp is a hint for the type to apply to the new node.
func (g *EscapeGraph) FieldSubnode(base *Node, field string, tp types.Type) *Node {
	reason := fieldSubnodeReason{field}
	if subnodes, ok := g.nodes.globalNodes.subnodes[base]; ok {
		if nodeData, ok := subnodes[reason]; ok {
			g.AddEdge(base, nodeData.node, EdgeSubnode)
			if g.rationales[base] != nil {
				g.rationales[nodeData.node] = g.rationales[base]
			}
			return nodeData.node
		}
		// TODO: don't repeat the following block and the (nearly but not quite) identical one below)
		f := g.nodes.NewNode(base.kind, field, tp)
		subnodes[reason] = nodeWithData{f, tp}
		g.nodes.globalNodes.parent[f] = nodeWithData{base, reason}
		g.AddEdge(base, f, EdgeSubnode)
		if g.rationales[base] != nil {
			g.rationales[f] = g.rationales[base]
		}
		return f
	}
	f := g.nodes.NewNode(base.kind, field, tp)
	g.nodes.globalNodes.subnodes[base] = map[any]nodeWithData{reason: {f, tp}}
	g.nodes.globalNodes.parent[f] = nodeWithData{base, reason}
	g.AddEdge(base, f, EdgeSubnode)
	if g.rationales[base] != nil {
		g.rationales[f] = g.rationales[base]
	}
	return f
}

// ImplementationSubnode returns the singular implementation subnode of `base`, with a given concrete type.
func (g *EscapeGraph) ImplementationSubnode(base *Node, concreteTp types.Type) *Node {
	reason := implementationSubnodeReason{fmt.Sprintf("%v", concreteTp)} // TODO: how to canonicalize the type?
	// Assert that we aren't creating a double impl subnode.
	if parentReason, ok := g.nodes.globalNodes.parent[base]; ok {
		if _, ok := parentReason.data.(implementationSubnodeReason); ok {
			panic("Adding implementation subnode to an existing subnode")
		}
	}
	if subnodes, ok := g.nodes.globalNodes.subnodes[base]; ok {
		if nodeData, ok := subnodes[reason]; ok {
			g.AddEdge(base, nodeData.node, EdgeSubnode)
			return nodeData.node // relationship already exists, return that node
		}
	} else {
		g.nodes.globalNodes.subnodes[base] = map[any]nodeWithData{}
	}
	subnodes := g.nodes.globalNodes.subnodes[base]
	f := g.nodes.NewNode(base.kind, fmt.Sprintf("impl: %s", concreteTp.String()), concreteTp)
	subnodes[reason] = nodeWithData{f, concreteTp}
	g.nodes.globalNodes.parent[f] = nodeWithData{base, reason}
	g.AddEdge(base, f, EdgeSubnode)
	return f
}

// IsSubnodeEdge returns whether base and n have a subnode relationship, from base to n.
// There may also be other edges between these two nodes.
func (g *EscapeGraph) IsSubnodeEdge(base, n *Node) bool {
	p, ok := g.nodes.globalNodes.parent[n]
	return ok && p.node == base
}

// IsSubnode returns true if n is a subnode of some other node.
func (g *EscapeGraph) IsSubnode(n *Node) bool {
	_, ok := g.nodes.globalNodes.parent[n]
	return ok
}

// AnalogousSubnode returns the subnode of base that has the same relationship with base that
// subnode has with its parent. Typically used to copy fields. For implementation subnodes, if base
// is not abstract (i.e. can't have subnodes), the result will be either the base node itself or
// nil, depending on whether the types match.
func (g *EscapeGraph) AnalogousSubnode(base *Node, subnode *Node) *Node {
	for reason, nodeData := range g.nodes.globalNodes.subnodes[g.nodes.globalNodes.parent[subnode].node] {
		if r, ok := reason.(fieldSubnodeReason); ok && nodeData.node == subnode {
			if nodeData.data == nil {
				return g.FieldSubnode(base, r.field, nil)
			}
			return g.FieldSubnode(base, r.field, nodeData.data.(types.Type))
		} else if _, ok := reason.(implementationSubnodeReason); ok && nodeData.node == subnode {
			subnodeType := nodeData.data.(types.Type)
			if baseTp, ok := g.nodes.globalNodes.types[base]; ok {
				// Check the base type, the type of the node we are adding a subnode for.
				// If it is abstract (e.g. interface type), create a subnode. Otherwise, if the
				// types are the same, then use the base node itself. If the types are different,
				// then return nil.
				if IsAbstractType(baseTp) {
					return g.ImplementationSubnode(base, subnodeType)
				} else if CompatibleTypes(subnodeType, baseTp) {
					return base
				} else {
					return nil
				}
			} else {
				// conservatively use a subnode, even if we don't have a type
				return g.ImplementationSubnode(base, subnodeType)
			}
		}
	}
	panic("Subnode argument is not a subnode: reason not found")
}

func (g *EscapeGraph) computeEdgeClosure(a, b *Node) {
	if g.status[a] > g.status[b] {
		g.status[b] = g.status[a]
		if g.status[a] == Leaked {
			if _, ok := g.rationales[b]; !ok {
				g.rationales[b] = g.rationales[a]
			}
		}
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
				if nodeStatus == Leaked {
					if _, ok := g.rationales[succ]; !ok {
						g.rationales[succ] = g.rationales[node]
					}
				}
				worklist = append(worklist, succ)
			}
		}
	}
}

// MergeNodeStatus sets the status of n to at least s. Doesn't modify the status if the current
// status is greater equal to s. Modifies g.
func (g *EscapeGraph) MergeNodeStatus(n *Node, s EscapeStatus, rationale *dataflow.EscapeRationale) {
	if oldStatus, ok := g.status[n]; !ok || s > oldStatus {
		g.status[n] = s
		if s == Leaked {
			g.rationales[n] = rationale
		}
	} else {
		return
	}
	for pointee := range g.edges[n] {
		g.computeEdgeClosure(n, pointee)
	}
}

// WeakAssign applies the weak-assignment operation `dest = src`. Basically, ensures that dest
// points to whatever src points to. Weak here means that it does not erase any existing edges from
// dest. Handles subnodes recursively, so it works for structure types, but does not generate load
// nodes (thus weak assign is only valid for src's that are local, such as ValueNodes). See also
// `copyStruct()`.
func (g *EscapeGraph) WeakAssign(dest *Node, src *Node) {
	g.AddNode(dest)
	for _, e := range g.Edges(src, nil, EdgeAll) {
		if e.isSubnode {
			destNode := g.AnalogousSubnode(dest, e.dest)
			g.WeakAssign(destNode, e.dest)
		} else {
			g.AddEdge(dest, e.dest, EdgeInternal)
		}
	}
}

func (g *EscapeGraph) getHistoryNodeOfOp(loadOp any, base *Node) *Node {
	node := base
	var historyNode *Node = nil
	for node != nil {
		associatedOps := g.nodes.loadOps[node]
		if associatedOps != nil && associatedOps[loadOp] {
			historyNode = node
		}
		if g.IsSubnode(node) {
			node = g.nodes.globalNodes.parent[node].node
		} else {
			node = g.nodes.loadBase[node]
		}
	}
	return historyNode
}

// EnsureLoadNode makes sure that if base is not local, then it has a node it points to.
// This can either be a new load node attached to base, or an existing node if the loadOp already
// created a load node somewhere in the base's history (this prevents infinite graphs). Regardless,
// the base node has an out-edge to this node. The node is returned, but there may be multiple
// external out-edges, and generally the specified load node should not be treated specially.
func (g *EscapeGraph) EnsureLoadNode(loadOp any, tp types.Type, base *Node) *Node {
	if g.status[base] == Local {
		return nil // do nothing if base is not external
	}
	// If tp is abstract, switch the load op to a generic one that is shared. This prevents a
	// factorial blowup when there are interfaces with implementations that have fields pointing to
	// the same interface, which can result in the analysis considering every possible way of
	// interleaving those objects. By giving all of these potential loads the same loadOp, we ensure
	// that the path has at most one node of each interface, which are usually much fewer than the
	// number of implementations.
	if IsAbstractType(tp) {
		loadOp = abstractTypeLoad{tp.String()}
	}
	// If this chain of load nodes already has the op, connect base to it (may create a back-edge or
	// a self-edge), and return that node.
	node := g.getHistoryNodeOfOp(loadOp, base)
	if node != nil {
		g.AddEdge(base, node, EdgeExternal)
		return node
	}
	// This op is not in base's history, so find or create a load node child of base
	loadNode := g.nodes.loadChild[base]
	if loadNode == nil {
		// We didn't find an existing child, so create one.
		tpStr := "?"
		if tp != nil {
			tpStr = tp.String()
		}
		loadNode = g.nodes.NewNode(KindLoad, fmt.Sprintf("%s load", tpStr), tp)
		g.AddEdge(base, loadNode, EdgeExternal)
		g.nodes.loadChild[base] = loadNode
		g.nodes.loadBase[loadNode] = base
		g.nodes.loadOps[loadNode] = map[any]bool{}
	}

	// Regardless of whether the node existed, make sure that we link base to it and that
	// the loadOp is recorded in the history for the load node
	g.AddEdge(base, loadNode, EdgeExternal)
	g.nodes.loadOps[loadNode][loadOp] = true
	return loadNode
}

// LoadField applies the load operation `valNode = *addrNode[.field]` and modifies g.
// This is a generalized operation: it also applies to reading the specified field from slices, maps, globals, etc.
// If field is empty (""), then dereference the object itself, otherwise dereference only the specified field.
// generateLoadNode is called to lazily create a node if the load can happen against an
// external object; this can't always be determined a priori, and we don't want to create a load node
// unless necessary.
func (g *EscapeGraph) LoadField(valNode *Node, addrNode *Node, loadOp any, field string, tp types.Type) {
	// Nodes are addr ->* addrPointee [.field] ->* doublePointee
	// val = *addr means we need to add edges from val to whatever node(s) *addr (i.e. all the addrPointees)'
	// points to. The addrPointees are the nodes that addr points to, and the doublePointees are collectively
	// everything that *addr points to. Thus we need to collect all double pointees and add edges
	// from val to these nodes.
	for addrPointee := range g.Pointees(addrNode) {
		// For non-empty fields, we take edges from the field subnode of each pointee. Otherwise, we are treating
		// the pointee itself as a pointer-like object, and taking edges from that.
		if field != "" {
			addrPointee = g.FieldSubnode(addrPointee, field, tp)
		}

		// if addrPointee is an escaped node, we need to add the load node
		g.EnsureLoadNode(loadOp, tp, addrPointee)

		// The double pointees are pointeeEdge.dest. Copy them to val
		g.WeakAssign(valNode, addrPointee)
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
	for addrPointee := range g.Pointees(addrNode) {
		if field != "" {
			addrPointee = g.FieldSubnode(addrPointee, field, tp)
		}
		g.WeakAssign(addrPointee, valNode)
	}
}

// Merge computes the union of this graph with another, used at e.g. the join-points of a dataflow graph. Modifies g in-place.
func (g *EscapeGraph) Merge(h *EscapeGraph) {
	for _, e := range h.Edges(nil, nil, EdgeAll) {
		g.AddEdge(e.src, e.dest, e.mask)
	}
	for node, s := range h.status {
		g.AddNode(node)
		g.MergeNodeStatus(node, s, h.rationales[node])
	}
}

// ReplaceBy sets the state of the graph to a copy of the argument `h`.
func (g *EscapeGraph) ReplaceBy(h *EscapeGraph) {
	hh := h.Clone()
	g.edges = hh.edges
	g.nodes = hh.nodes
	g.rationales = hh.rationales
	g.status = hh.status
}

// AsImplInterfaceType returns the corresponding interface type, if the input is is an abstract
// interface implementation type, otherwise it returns nil.
func AsImplInterfaceType(a types.Type) types.Type {
	if aa, ok := a.(*ImplType); ok {
		if _, ok := aa.tp.Underlying().(*types.Interface); ok {
			return aa.tp
		}
	}
	return nil
}

// CompatibleTypes returns true if a node of tpA can represent a node of tpB. Conservatively return
// true if either doesn't have a type (represented by tpA or tpB being nil). Represent here means
// that tpA is tpB or tpA satisfies the interface tpB.
func CompatibleTypes(tpA, tpB types.Type) (r bool) {
	// Swallow errors caused by supplying our custom ImplType as types.Type to the types package
	defer func() {
		if x := recover(); x != nil {
			r = true
		}
	}()
	// Allow nil
	if tpA == nil || tpB == nil {
		return true
	}
	if iType := AsImplInterfaceType(tpB); iType != nil {
		return types.AssignableTo(tpA, iType) || types.AssignableTo(types.NewPointer(tpA), iType)
	}
	if types.AssignableTo(tpA, tpB) {
		return true
	}
	return false
}

// IsAbstractType returns true if the input is an abstract type, i.e. an interface impl or a
// function impl with no specific function.
func IsAbstractType(tp types.Type) (r bool) {
	switch t := tp.(type) {
	case *ImplType:
		switch t.tp.Underlying().(type) {
		case *types.Interface:
			return true
		default:
			return false
		}
	case *FunctionImplType:
		return t.fun == nil
	case *types.Named:
		return IsAbstractType(tp.Underlying())
	default:
		return false
	}
}
func isAbstractNode(g *EscapeGraph, n *Node) bool {
	if tp, ok := g.nodes.globalNodes.types[n]; ok {
		return IsAbstractType(tp)
	}
	return false
}

// Call computes the result of splicing in the summary (callee) of the callee's graph. args are the
// nodes corresponding to the caller's actual parameters at the callsite (nil if not pointer-like).
// rets are the nodes corresponding to the caller values to assign the results to (nil if not
// pointer-like). callee is the summary of the called function.
//
//gocyclo:ignore
func (g *EscapeGraph) Call(pre *EscapeGraph, receiver *Node, args []*Node, freeVars []*Node, rets []*Node, callee *EscapeGraph) {
	type uEdge struct {
		src, dest *Node
	}
	// u maps nodes in summary to the nodes in the caller
	u := map[*Node]map[uEdge]struct{}{}
	// deferredReps are used to ensure one of the rules triggers consistently
	deferredReps := map[*Node]map[uEdge]struct{}{}
	var receiverInCallee *Node = nil
	if receiver != nil {
		receiverInCallee = callee.nodes.formals[0]
	}
	worklist := []uEdge{}
	addUEdge := func(x, y *Node) {
		// Redirect u edges that would be from a concrete node in the callee to an abstract node in
		// the caller, so that they point at the implementation subnode of the correct type.
		if tp, ok := g.nodes.globalNodes.types[x]; ok && isAbstractNode(pre, y) && !isAbstractNode(g, x) {
			y = g.ImplementationSubnode(y, tp)
		}
		e := uEdge{x, y}
		if m, ok := u[x]; ok {
			if _, ok := m[e]; ok {
				return
			}
			m[e] = struct{}{}
		} else {
			u[x] = map[uEdge]struct{}{e: {}}
		}
		worklist = append(worklist, e)
	}
	addDeferredRep := func(x *Node, e uEdge) {
		if m, ok := deferredReps[x]; ok {
			m[e] = struct{}{}
		} else {
			deferredReps[x] = map[uEdge]struct{}{e: {}}
		}
	}
	// Adds an edge, but only if there isn't already and edge between src and dest's implementation
	// parent (if it has one). Such edges are already implied, and are therefore redundant. This may
	// not prevent all such redundant edges, as this only works if the edge to the subnode is added
	// after the edge to the parent.
	addEdge := func(src, dest *Node, m edgeFlags) {
		var existingParentEdgeFlags edgeFlags = 0
		if parentReason, ok := g.nodes.globalNodes.parent[dest]; ok {
			if _, ok := parentReason.data.(implementationSubnodeReason); ok {
				if outEdges, ok := g.edges[src]; ok {
					existingParentEdgeFlags = outEdges[parentReason.node]
				}
			}
		}
		flagsToSet := m & (^existingParentEdgeFlags)
		if flagsToSet == 0 {
			return
		}
		g.AddEdge(src, dest, flagsToSet)
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
		if (freeVars[i] == nil) != (freevar == nil) {
			panic("Incorrect nil-ness of corresponding free var nodes")
		}
		if freevar != nil {
			addUEdge(freevar, freeVars[i])
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
			for _, baseEdge := range callee.Edges(base, nil, EdgeAll) {
				if !baseEdge.isInternal {
					for v := range pre.edges[rep] {
						addUEdge(baseEdge.dest, v)
					}
				}
			}
		}

		// propagate internal edges created in the callee
		// Creates a new edge rep --> x in the following:
		// rep -------> x
		//  |           |
		//  | u         | u
		//  |           |
		// base ------> y
		// If the right u edge is added first, then when we process base/rep, we will
		// add the right thing. But if the left edge is added first, then we will miss adding
		// an edge as there will be no u edges from y -> x. Therefore, we add a "deferredRep"
		// edge from y to rep. If y -> x is ever added later, then the case below will trigger
		// and the edge will be completed.
		if base.kind != KindParamVar {
			for _, edge := range callee.Edges(base, nil, EdgeInternal|EdgeSubnode) {
				if edge.isSubnode {
					// This is a special subnode edge, add the analogous edge in the caller graph, and link
					fieldNode := g.AnalogousSubnode(rep, edge.dest)
					if fieldNode != nil {
						addUEdge(edge.dest, fieldNode)
					}
				} else {
					// Normal edge, y is edge.dest
					for uEdge := range u[edge.dest] {
						addEdge(rep, uEdge.dest, EdgeInternal)
					}
					// Edge.dest will be overwritten by whatever x ends up being, so leave it nil.
					addDeferredRep(edge.dest, uEdge{rep, nil})
				}
			}
		}

		// Add edges for the pointees of parameters, to link them with their representatives in the
		// caller. This happens here so that we can handle subnodes appropriately. Subnodes still
		// have the kind of their parent, so e.g. fields of a parameter are still KindParamVar,
		// which causes this rule to trigger recursively to match up all the fields of struct-type
		// parameters.
		if base.kind == KindParamVar {
			for _, edge := range callee.Edges(base, nil, EdgeAll) {
				if edge.isSubnode {
					// This is a special subnode edge
					// find the subnode relationship
					fieldNode := g.AnalogousSubnode(rep, edge.dest)
					addUEdge(edge.dest, fieldNode)
				} else {
					for p := range pre.Pointees(rep) {
						if !pre.IsSubnodeEdge(rep, p) {
							// Filter out pointees of the receiver that do not have the correct
							// type. This is how we ensure the method is only applied to nodes of
							// the correct type. addUEdge will handle the case where the pointee is
							// an interface node by redirecting to the appropriate subnode.
							compat := CompatibleTypes(g.nodes.globalNodes.types[edge.dest], g.nodes.globalNodes.types[p])
							if base != receiverInCallee || compat {
								addUEdge(edge.dest, p)
							}
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
		for e := range deferredReps[base] {
			addEdge(e.src, rep, EdgeInternal)
		}

		// propagate allocations/possible allocations (from un-analyzed functions)/globals
		// Adds node alloc to g, and adds the mapping edge u'
		// rep          alloc
		//  |           |
		//  | u         | u'
		//  |           |
		// base ------> alloc
		// Rep is required to exist but we don't do anything with it. This makes sure
		// we only add the alloc node if it will be visible in the caller
		for _, edge := range callee.Edges(base, nil, EdgeAll) {
			isInternalToAllocNode := edge.isInternal && (edge.dest.kind == KindAlloc || edge.dest.kind == KindUnknown || edge.dest.kind == KindGlobal)

			if isInternalToAllocNode {
				g.nodes.AddForeignNode(edge.dest)
				g.AddNode(edge.dest)
				addUEdge(edge.dest, edge.dest)
			}
		}

		// propagate load nodes that are referenced by escaped nodes
		// Adds node load' to g, and adds the mapping edge u' and edge rep - -> load'
		// rep  - - -> load'
		//  |           |
		//  | u         | u'
		//  |           |
		// base - - -> load
		// Rep is required to be escaped (if rep didn't exist, use status from new graph).

		if status, ok := pre.status[rep]; (!ok && g.status[rep] != Local) || status != Local {
			for _, edge := range callee.Edges(base, nil, EdgeAll) {
				if (!edge.isInternal || base.kind == KindGlobal) && edge.dest.kind == KindLoad {
					loadNode := edge.dest
					for op := range callee.nodes.loadOps[loadNode] {
						loadNodeCaller := g.EnsureLoadNode(op, g.nodes.globalNodes.types[loadNode], rep)
						addUEdge(loadNode, loadNodeCaller)
					}
				}
			}
		}
		// Propagating "escaped" information is tricky. We need to make a distinction between things
		// that could have escaped to the heap, and just things that are parameters/loads from the callee's
		// perspective. This means that we propagate "leaked" along u edges but not "escaped."
		if callee.status[base] == Leaked {
			g.MergeNodeStatus(rep, Leaked, callee.rationales[base])
		}
	}
}

// CallUnknown computes the result of calling an unknown function. An unknown function has no bound
// on its allowed semantics. This means that the arguments are assumed to leak, and the return value
// is treated similarly to a load node, except it can never be resolved with arguments like loads
// can be.
func (g *EscapeGraph) CallUnknown(args []*Node, rets []*Node, funcName string) {
	for _, arg := range args {
		for n := range g.Pointees(arg) {
			r := dataflow.NewBaseRationale(fmt.Sprintf("argument to %s", funcName))
			g.MergeNodeStatus(n, Leaked, r)
		}
	}
	for _, ret := range rets {
		g.AddEdge(ret, g.nodes.UnknownReturnNode(funcName), EdgeInternal)
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
	for _, gEdge := range g.Edges(nil, nil, EdgeAll) {
		if len(h.Edges(gEdge.src, gEdge.dest, gEdge.mask)) == 0 {
			return false, fmt.Sprintf("missing edge %v -> %v (internal: %v)", gEdge.src, gEdge.dest, gEdge.isInternal)
		}
	}
	for node, gStatus := range g.status {
		if hStatus, ok := h.status[node]; ok {
			if gStatus > hStatus {
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
	nextNode        int
	function        map[*Node]*ssa.Function
	globals         map[*ssa.Global]*Node
	staticFunctions map[*ssa.Function]*Node
	subnodes        map[*Node]map[any]nodeWithData // map from root node to reasons to subnode children
	parent          map[*Node]nodeWithData         // nodes can only have one parent for now; subnodes form a forest. value has parent + reason
	types           map[*Node]types.Type
	// TODO: introduce a mutex around nextNode for multithreading
}

func newGlobalNodeGroup() *globalNodeGroup {
	return &globalNodeGroup{0,
		make(map[*Node]*ssa.Function),
		make(map[*ssa.Global]*Node),
		make(map[*ssa.Function]*Node),
		make(map[*Node]map[any]nodeWithData),
		make(map[*Node]nodeWithData),
		make(map[*Node]types.Type)}
}

// getNewID generates a new globally unique id for a node. The id is used to uniquely identify
// nodes without needing to rely on addresses (i.e. for debugging) and provides a way to sort
// nodes that is deterministic (as long as node creation is deterministic).
func (gn *globalNodeGroup) getNewID() int {
	i := gn.nextNode
	gn.nextNode++
	return i
}

type instructionIndex struct {
	instr ssa.Instruction
	index string
}

// A NodeGroup stores the identity of nodes within a current function context, and ensures
// that e.g. a single load node is shared between all invocations of a load instruction, or
// all allocations in a particular function.
type NodeGroup struct {
	variables     map[ssa.Value]*Node
	allocs        map[instructionIndex]*Node
	loads         map[any]*Node
	loadOps       map[*Node]map[any]bool
	loadBase      map[*Node]*Node
	loadChild     map[*Node]*Node
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
		make(map[instructionIndex]*Node),
		make(map[any]*Node),
		make(map[*Node]map[any]bool),
		make(map[*Node]*Node),
		make(map[*Node]*Node),
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
	node, ok := g.allocs[instructionIndex{instr, ""}]
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
	g.allocs[instructionIndex{instr, ""}] = node
	g.globalNodes.types[node] = t
	return node
}

// IndexedAllocNode creates a node that represents an allocation. It is similar to AllocNode, but
// allows more than one allocated node per instruction, keyed by an additional index string.
func (g *NodeGroup) IndexedAllocNode(instr ssa.Instruction, index string, t types.Type) *Node {
	node, ok := g.allocs[instructionIndex{instr, index}]
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
	g.allocs[instructionIndex{instr, index}] = node
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
	// Of these, SSA variables (ssa.Instruction), Parameters, Functions, FreeVar, nil, and Globals have nodes.
	// Builtins and Constants (that aren't nil) should not be passed to this function
	if _, ok := variable.(*ssa.Builtin); ok {
		panic("Not expecting built-in")
	}
	if c, ok := variable.(*ssa.Const); ok {
		if c.IsNil() {
			return g.NilNode()
		}
		// since x/tools v0.9 struct constants appear as values.
		if _, isStruct := c.Type().Underlying().(*types.Struct); !isStruct {
			panic("Non-nil constant not supported" + fmt.Sprintf("%v", variable))
		}
	}

	node, ok := g.variables[variable]
	if ok {
		return node
	}
	kind := KindVar
	kindStr := ""
	if _, ok := variable.(*ssa.Global); ok {
		kind = KindGlobalVar
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
func (g *NodeGroup) NewNode(kind nodeKind, debug string, tp types.Type) *Node {
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
// manual summary written for them.
func (g *NodeGroup) UnknownReturnNode(funcName string) *Node {
	if g.unknownReturn != nil {
		return g.unknownReturn
	}
	node := &Node{KindUnknown, g.globalNodes.getNewID(), fmt.Sprintf("unknown return of %s", funcName)}
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

// GlobalNode returns the global node representing the target (storage location) of a global
// variable. It is pointed at by a corresponding KindGlobalVar.
func (gn *globalNodeGroup) GlobalNode(global *ssa.Global) *Node {
	node, ok := gn.globals[global]
	if ok {
		return node
	}
	node = &Node{KindGlobal, gn.getNewID(), fmt.Sprintf("*%s %v", global.Name(), NillableDerefType(global.Type()))}
	gn.globals[global] = node
	gn.types[node] = NillableDerefType(global.Type())
	return node
}

// StaticFunctionNode returns the global node representing a static function, so that it can be the
// pointee of a closure. This allows a closure object that represents taking a pointer to a static function.
func (gn *globalNodeGroup) StaticFunctionNode(f *ssa.Function) *Node {
	node, ok := gn.staticFunctions[f]
	if ok {
		return node
	}
	node = &Node{KindGlobal, gn.getNewID(), fmt.Sprintf("static func %v", f.Name())}
	gn.staticFunctions[f] = node
	gn.types[node] = &FunctionImplType{f.Signature, f}
	gn.function[node] = f
	return node
}
