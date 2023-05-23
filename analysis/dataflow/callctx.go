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

// Functions in this file are experimental: our analyses are not context-sensitive for the time being!

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/awslabs/argot/internal/funcutil"
	. "github.com/awslabs/argot/internal/graphutil"
	cg "golang.org/x/tools/go/callgraph"
)

type CallCtxInfo struct {
	Contexts map[string]bool
	Ids      map[int]*cg.Node
}

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
	return strings.Join(Map(calls, func(c *cg.Node) string { return strconv.Itoa(c.ID) }), ".")
}

func ComputeCtxts(c *AnalyzerState, n int) (CallCtxInfo, error) {
	ci := CallCtxInfo{
		Contexts: map[string]bool{},
		Ids:      map[int]*cg.Node{},
	}

	root := c.PointerAnalysis.CallGraph.Root

	if root == nil {
		return ci, fmt.Errorf("nil root")
	}
	que := []*Tree[*cg.Node]{NewTree(root)}

	for len(que) > 0 {
		cur := que[0]

		que = que[1:]
		if cur.Label == nil {
			continue
		}
		ci.Ids[cur.Label.ID] = cur.Label
		key := callCtxKey(Map(cur.Ancestors(n), Label[*cg.Node]))
		if !ci.Contexts[key] {
			ci.Contexts[key] = true
			for _, e := range cur.Label.Out {
				que = append(que, cur.AddChild(e.Callee))
			}
		}
	}
	return ci, nil
}
