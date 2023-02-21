package dataflow

import "strings"

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

	// len memoizes the height of the tree
	height int
}

func NewNodeTree[T GraphNode](initNode T) *NodeTree[T] {
	origin := &NodeTree[T]{Label: initNode, Parent: nil, Children: []*NodeTree[T]{}, height: 1}
	origin.Origin = origin
	return origin
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

// Len returns the height of the node tree (length of a path from the root to the current node
func (n *NodeTree[T]) Len() int {
	if n == nil {
		return 0
	} else {
		return n.height
	}
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

// IsLasso checks if the trace (path from root to node) is more than one node long and the current node has the same
// call as the last node.
func (n *NodeTree[T]) IsLasso() bool {
	if n == nil || n.height <= 1 {
		return false
	}
	last := n
	for cur := last.Parent; cur != nil; cur = cur.Parent {
		if cur.Label.String() == last.Label.String() {
			return true
		}
	}
	return false
}

// Add appends a node to the current node's children and return the newly created child
func (n *NodeTree[T]) Add(node T) *NodeTree[T] {
	if n == nil {
		return NewNodeTree(node)
	} else {
		newNode := &NodeTree[T]{Label: node, Parent: n, Children: []*NodeTree[T]{}, Origin: n.Origin, height: n.height + 1}
		n.Children = append(n.Children, newNode)
		return newNode
	}
}

// FuncNames returns a string that contains all the function names in the current trace (from root to leaf)
func FuncNames(n *NodeTree[*CallNode]) string {
	if n == nil || n.height == 0 {
		return ""
	}
	s := make([]string, n.height)
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.height >= 1 {
			s[cur.height-1] = cur.Label.FuncName()
		}
	}
	return strings.Join(s, "->")
}

// ClosureNames reutrns a string that contains all the closure names in the current trace
func ClosureNames(n *NodeTree[*ClosureNode]) string {
	if n == nil || n.height == 0 {
		return ""
	}
	s := make([]string, n.height)
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.height >= 1 {
			s[cur.height-1] = cur.Label.Instr().Fn.Name()
		}
	}
	return strings.Join(s, "->")
}
