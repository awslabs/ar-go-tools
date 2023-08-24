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

// VisitorNode represents a node in the inter-procedural dataflow graph to be visited.
type VisitorNode struct {
	NodeWithTrace
	ParamStack *ParamStack
	Prev       *VisitorNode
	Depth      int
	children   []*VisitorNode
}

func (v *VisitorNode) AddChild(c *VisitorNode) {
	v.children = append(v.children, c)
}

// ParamStack represents a stack of parameters.
type ParamStack struct {
	Param *ParamNode
	Prev  *ParamStack
}

// Add adds p to the stack.
func (ps *ParamStack) Add(p *ParamNode) *ParamStack {
	return &ParamStack{Param: p, Prev: ps}
}

// Parent returns the previous param in the stack.
func (ps *ParamStack) Parent() *ParamStack {
	if ps == nil {
		return nil
	} else {
		return ps.Prev
	}
}

// addNext adds the node to the queue que, setting cur as the previous node and checking that node with the
// trace has not been seen before
func addNext(c *AnalyzerState,
	que []*VisitorNode,
	seen map[NodeWithTrace]bool,
	cur *VisitorNode,
	node GraphNode,
	trace *NodeTree[*CallNode],
	closureTrace *NodeTree[*ClosureNode]) []*VisitorNode {

	newNode := NodeWithTrace{Node: node, Trace: trace, ClosureTrace: closureTrace}

	// Stop conditions: node is already in seen, trace is a lasso or depth exceeds limit
	if seen[newNode] || trace.GetLassoHandle() != nil || c.Config.ExceedsMaxDepth(cur.Depth) {
		return que
	}

	// logic for parameter stack
	pStack := cur.ParamStack
	switch curNode := cur.Node.(type) {
	case *ReturnValNode:
		pStack = pStack.Parent()
	case *ParamNode:
		pStack = pStack.Add(curNode)
	}

	newVis := &VisitorNode{
		NodeWithTrace: newNode,
		ParamStack:    pStack,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	que = append(que, newVis)
	seen[newNode] = true
	return que
}
