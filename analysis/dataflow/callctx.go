package dataflow

// Functions in this file are experimental: our analyses are not context-sensitive for the time being!

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/awslabs/argot/analysis/functional"
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

func ComputeCtxts(c *Cache, n int) (CallCtxInfo, error) {
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
