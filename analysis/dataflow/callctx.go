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
	"fmt"
	"strconv"
	"strings"

	funcs "github.com/awslabs/ar-go-tools/internal/funcutil"
	graphs "github.com/awslabs/ar-go-tools/internal/graphutil"
	cg "golang.org/x/tools/go/callgraph"
)

// GetAllCallingContexts returns all the possible loop-free calling contexts of a CallNode in the state
func GetAllCallingContexts(s *AnalyzerState, n *CallNode) []*CallStack {
	if s.PointerAnalysis == nil {
		return nil
	}

	var que []*CallStack
	visited := map[*CallNode]bool{}

	for _, e := range s.PointerAnalysis.CallGraph.Root.Out {
		summary := s.FlowGraph.Summaries[e.Callee.Func]
		if summary != nil {
			for _, callNodeSet := range summary.Callees {
				for _, callNode := range callNodeSet {
					que = append(que, NewNodeTree(callNode))
				}
			}
		}
	}
	var results []*CallStack

	for len(que) > 0 {
		elt := que[0]
		que = que[1:]
		if elt.Label == n {
			results = append(results, elt)
		}
		visited[elt.Label] = true
		if elt.Label.CalleeSummary != nil {
			for _, callNodeSet := range elt.Label.CalleeSummary.Callees {
				for _, callNode := range callNodeSet {
					if !visited[callNode] {
						que = append(que, elt.Add(callNode))
					}
				}
			}
		}
	}

	return results
}

// Following functions are experimental: our analyses are not context-sensitive for the time being!

// CallCtxInfo holds information about a calling context of a function
type CallCtxInfo struct {
	Contexts map[string]bool
	Ids      map[int]*cg.Node
}

// KeyToNodes returns the list of nodes matching the dot-separated string used as key in a context
func (c CallCtxInfo) KeyToNodes(key string) []*cg.Node {
	var nodes []*cg.Node
	ids := strings.Split(key, ".")
	for _, elt := range ids {
		if i, err := strconv.Atoi(elt); err == nil {
			node := c.Ids[i]
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func callCtxKey(calls []*cg.Node) string {
	return strings.Join(funcs.Map(calls, func(c *cg.Node) string { return strconv.Itoa(c.ID) }), ".")
}

// ComputeContexts computes all calling contexts of size at most n
// (the callgraph used is in c.PointerAnalysis.Callgraph.Root)
func ComputeContexts(c *AnalyzerState, n int) (CallCtxInfo, error) {
	ci := CallCtxInfo{
		Contexts: map[string]bool{},
		Ids:      map[int]*cg.Node{},
	}

	root := c.PointerAnalysis.CallGraph.Root

	if root == nil {
		return ci, fmt.Errorf("nil root")
	}
	que := []*graphs.Tree[*cg.Node]{graphs.NewTree(root)}

	for len(que) > 0 {
		cur := que[0]

		que = que[1:]
		if cur.Label == nil {
			continue
		}
		ci.Ids[cur.Label.ID] = cur.Label
		key := callCtxKey(funcs.Map(cur.Ancestors(n), graphs.Label[*cg.Node]))
		if !ci.Contexts[key] {
			ci.Contexts[key] = true
			for _, e := range cur.Label.Out {
				que = append(que, cur.AddChild(e.Callee))
			}
		}
	}
	return ci, nil
}
