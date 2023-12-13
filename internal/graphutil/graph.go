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

package graphutil

import (
	"sort"

	"golang.org/x/tools/go/callgraph"
	"gonum.org/v1/gonum/graph"
)

// CGraph is an abstraction over a callgraph to work with existing graph libraries. It implements the methods to
// satisfy graph.Iterator and Gonum's graph.Graph
type CGraph struct {
	// The order of the graph
	order int

	// The original callgraph the CGraph was constructed from
	Graph *callgraph.Graph

	// IDMap maps from node IDs to CNodes
	IDMap map[int64]CNode

	// Keys are all the node IDs
	Keys []int64

	// Edges is an adjacency matrix: Edges[x][y] means there is a directed edge between IDMap[x] and IDMap[y]
	Edges map[int64]map[int64]bool
}

// NewCallgraphIterator returns a new call graph iterator where node ids correspond the Node.ID of each callgraph node
func NewCallgraphIterator(cg *callgraph.Graph) CGraph {
	n := len(cg.Nodes)
	idmap := make(map[int64]CNode, n)
	edges := make(map[int64]map[int64]bool, n)
	keys := make([]int64, n)
	i := 0
	for _, node := range cg.Nodes {

		keys[i] = int64(node.ID)
		i++

		idmap[int64(node.ID)] = CNode{node}
		edges[int64(node.ID)] = map[int64]bool{}
		for _, e := range node.Out {
			if e.Callee != nil {
				edges[int64(node.ID)][int64(e.Callee.ID)] = true
			}
		}
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	return CGraph{
		order: len(cg.Nodes),
		Graph: cg,
		IDMap: idmap,
		Edges: edges,
		Keys:  keys,
	}
}

// Subgraph returns a new graph that is the original graph with only the nodes in include. Only the edges that have
// both the origin and destination nodes in the include nodes are kept in the resulting graph.
// The subgraph's order, Graph and IDMap are the same as in origin, meaning that node indices will stay consistent
// across subgraphs.
func Subgraph(original CGraph, include []int64) CGraph {
	idmap := make(map[int64]CNode, len(include))
	edges := make(map[int64]map[int64]bool, len(include))
	keys := make([]int64, len(include))

	for j, i := range include {
		keys[j] = i
		idmap[i] = original.IDMap[i]
	}

	for _, i := range include {
		edges[i] = map[int64]bool{}
		for e := range original.Edges[i] {
			if _, ok := idmap[e]; ok {
				edges[i][e] = true
			}
		}
	}

	return CGraph{
		order: original.Order(),
		Graph: original.Graph,
		IDMap: original.IDMap,
		Edges: edges,
		Keys:  keys,
	}
}

// Order implements the order of the graph.Iterator interface for the CGraph
func (c CGraph) Order() int {
	return c.order
}

// Visit implements the graph.Iterator interface for the CGraph
func (c CGraph) Visit(v int, do func(w int, c int64) (skip bool)) (aborted bool) {
	if _, ok := c.IDMap[int64(v)]; !ok {
		return false
	}
	for w := range c.Edges[int64(v)] {
		if do(int(w), 1) {
			return true
		}
	}
	return false
}

// *************** Graph interface implementation **********************

// Node implements the Graph interface
func (c CGraph) Node(v int) graph.Node {
	return c.IDMap[int64(v)]
}

// Nodes returns the set of nodes in the graph
func (c CGraph) Nodes() graph.Nodes {
	keys := make([]int64, len(c.IDMap))

	i := 0
	for k := range c.IDMap {
		keys[i] = k
		i++
	}
	return &NodeSet{
		nodes: c.IDMap,
		ids:   keys,
		cur:   0,
	}
}

// From returns the set of nodes reachable from the id
func (c CGraph) From(id int64) graph.Nodes {
	var keys []int64

	for out := range c.Edges[id] {
		keys = append(keys, out)
	}
	return &NodeSet{
		nodes: c.IDMap,
		ids:   keys,
		cur:   0,
	}
}

// HasEdgeBetween returns a boolean indicating whether an edge exists between the two node identifiers
func (c CGraph) HasEdgeBetween(xid, yid int64) bool {
	xe := c.Edges[xid]
	ye := c.Edges[yid]
	return xe[yid] || ye[xid]
}

// Edge returns the edge between the two identifiers (nil if none exists)
func (c CGraph) Edge(uid, vid int64) graph.Edge {
	ue := c.Edges[uid]
	if ue != nil {
		if ue[vid] {
			return CEdge{from: c.IDMap[uid], to: c.IDMap[vid]}
		}
	}
	return nil
}

// *************** Nodes implementation **********************

// CNode is a wrapper around a *callgraph.Node that implements the graph.Node interface
type CNode struct {
	Node *callgraph.Node
}

// ID returns the id of the node
func (n CNode) ID() int64 {
	return int64(n.Node.ID)
}

func (n CNode) String() string {
	if n.Node == nil {
		return ""
	}
	return n.Node.String()
}

// NodeSet implements the graph.Nodes interface, an iterator over a set of nodes
type NodeSet struct {
	// nodes is the set of nodes in the iterator
	nodes map[int64]CNode

	// ids is the set of node ids in the iterator
	// invariant: len(ids) = len(nodes)
	ids []int64

	// cur is the current index of the iterator. The current node is nodes[ids[cur]]
	// invariant: 0 <= cur < len(nodes)
	cur int
}

// Next moves the current node to the next, and returns true if such a node exists. Otherwise, returns false
// and the current node has not changed.
func (ns *NodeSet) Next() bool {
	if ns.cur < len(ns.ids)-1 {
		ns.cur++
		return true
	}
	return false
}

// Len returns the length of the node set
func (ns *NodeSet) Len() int {
	return len(ns.ids)
}

// Reset resets the id of the current node in the set
func (ns *NodeSet) Reset() {
	ns.cur = 0
}

// Node return the current node in the set
func (ns *NodeSet) Node() graph.Node {
	return ns.nodes[ns.ids[ns.cur]]
}

// *************** Edge implementation **********************

// CEdge implements the graph.Edge interface
type CEdge struct {
	from CNode
	to   CNode
}

// From returns the origin of the edge
func (e CEdge) From() graph.Node {
	return e.from
}

// To returns the destination of the edge
func (e CEdge) To() graph.Node {
	return e.to
}

// ReversedEdge returns a new value representing the reversed edge
func (e CEdge) ReversedEdge() graph.Edge {
	return CEdge{from: e.to, to: e.from}
}
