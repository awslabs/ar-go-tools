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

type VisitorKind = int

const (
	// Default is for the default dataflow analysis mode
	Default VisitorKind = 1 << iota
	// ClosureTracing denotes the mode where the visitor is used to follow a closure
	ClosureTracing
)

// VisitorNodeStatus represents the status of a visitor node. It is either in default mode, in which case
// the Index does not mean anything, or it is in ClosureTracing mode, in which case the index represents the index of
// the bound variable that needs to be traced to a closure call.
type VisitorNodeStatus struct {
	Kind                VisitorKind
	Index               int
	ClosureSummaryGraph *SummaryGraph
}

// VisitorNode represents a node in the inter-procedural dataflow graph to be visited.
type VisitorNode struct {
	NodeWithTrace
	Prev     *VisitorNode
	Depth    int
	Status   VisitorNodeStatus
	children []*VisitorNode
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

	newVis := &VisitorNode{
		NodeWithTrace: newNode,
		Prev:          cur,
		Depth:         cur.Depth + 1,
	}
	que = append(que, newVis)
	seen[newNode] = true
	return que
}
