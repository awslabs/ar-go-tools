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
	"strings"
)

// KeyType is a value type to represents keys
type KeyType = string

// NodeWithTrace represents a GraphNode with two traces, a Trace for the call stack at the node and a ClosureTrace for
// the stack of makeClosure instructions at the node
type NodeWithTrace struct {
	Node         GraphNode
	Trace        *NodeTree[*CallNode]
	ClosureTrace *NodeTree[*ClosureNode]
}

// Key generates an object of type KeyType whose *value* identifies the value of g uniquely.
// If two NodeWithTrace objects represent the same node with the same call and closure traces, the Key() method
// will return the same value
func (g NodeWithTrace) Key() KeyType {
	s := g.Node.LongID() + "!" + g.Trace.Key() + "!" + g.ClosureTrace.Key()
	return s
}

// CallStack represents call stacks as trees of call nodes
// One can point at a specific node in the tree and extract the call stack above
type CallStack = NodeTree[*CallNode]

// NodeTree is a data structure to represent node trees built during the traversal of the interprocedural data flow
// graph.
type NodeTree[T GraphNode] struct {
	// Label is the graph node linked to the current NodeTree
	Label T

	// Origin is the root of the node tree
	Origin *NodeTree[T]

	// Parent is the parent of the current node
	Parent *NodeTree[T]

	Children []*NodeTree[T]

	// height memorizes the height of the tree
	height int

	key string
}

// NewNodeTree returns a new node tree with the initial node label provided
func NewNodeTree[T GraphNode](initNode T) *NodeTree[T] {
	origin := &NodeTree[T]{
		Label:  initNode,
		Parent: nil, Children: []*NodeTree[T]{},
		height: 1,
		key:    initNode.LongID(),
	}
	origin.Origin = origin
	return origin
}

// Key returns the key of the node. If the node has been constructed only using NewNodeTree and Add, the key will be
// unique for each node. If the node is nil, returns the empty string.
//
// (nil-safe)
func (n *NodeTree[T]) Key() string {
	if n == nil {
		return ""
	}
	return n.key
}

func (n *NodeTree[T]) String() string {
	if n == nil || n.height == 0 {
		return ""
	}
	s := make([]string, n.height)
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.height >= 1 {
			s[cur.height-1] = cur.Label.String()
		}
	}
	return strings.Join(s, "_")
}

// SummaryString returns a short summary of n.
func (n *NodeTree[T]) SummaryString() string {
	if n == nil || n.height == 0 {
		return ""
	}
	s := make([]string, n.height)
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.height >= 1 {
			s[cur.height-1] = shortNodeSummary(cur.Label)
		}
	}
	return strings.Join(s, "->") // -> is more readable for shorter nodes than _
}

// Len returns the height of the node tree (length of a path from the root to the current node
func (n *NodeTree[T]) Len() int {
	if n == nil {
		return 0
	}
	return n.height
}

// ToSlice returns a slice of the nodes on the path from the root to the current node. The elements are ordered with
// the root first and the current node last.
func (n *NodeTree[T]) ToSlice() []T {
	if n == nil {
		return []T{}
	}
	s := make([]T, n.height)
	pos := n.height - 1
	for cur := n; cur != nil; cur = cur.Parent {
		s[pos] = cur.Label
		pos--
	}
	return s
}

// GetLassoHandle checks if the trace (path from root to node) is more than one node long and the current node has the same
// call as the last node. If the trace is a lasso, the end of the handle is returned. Otherwise, the function returns
// nil.
//
// (nil safe)
func (n *NodeTree[T]) GetLassoHandle() *NodeTree[T] {
	if n == nil || n.height <= 1 {
		return nil
	}
	last := n
	for cur := last.Parent; cur != nil; cur = cur.Parent {
		if cur.Label.String() == last.Label.String() {
			return cur
		}
	}
	return nil
}

// Add appends a node to the current node's children and return the newly created child
func (n *NodeTree[T]) Add(node T) *NodeTree[T] {
	if n == nil {
		return NewNodeTree(node)
	}
	// Check that the child node is not already there
	for _, ch := range n.Children {
		if ch.Label.Equal(node) {
			return ch
		}
	}

	// A new node needs to be allocated
	newNode := &NodeTree[T]{
		Label:    node,
		Parent:   n,
		Children: []*NodeTree[T]{},
		Origin:   n.Origin,
		height:   n.height + 1,
		key:      n.key + "-" + node.LongID(),
	}
	n.Children = append(n.Children, newNode)
	return newNode
}

func (n *NodeTree[T]) Append(tree *NodeTree[T]) *NodeTree[T] {
	if tree == n {
		return n
	}
	s := tree.ToSlice()
	if len(s) == 0 {
		return n
	}
	if !n.Label.Equal(s[0]) {
		return nil
	}
	cur := n
	for _, e := range s[1:] {
		cur = cur.Add(e)
	}
	return cur
}

// FuncNames returns a string that contains all the function names in the current trace (from root to leaf)
func FuncNames(n *NodeTree[*CallNode], debug bool) string {
	if n == nil || n.height == 0 {
		return ""
	}
	s := make([]string, n.height)
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.height >= 1 {
			// if debug is set, add the internal id
			if debug {
				s[cur.height-1] = "(" + cur.Label.LongID() + ")" + cur.Label.FuncName()
			} else {
				s[cur.height-1] = cur.Label.FuncName()
			}
		}
	}
	return strings.Join(s, "->")
}
