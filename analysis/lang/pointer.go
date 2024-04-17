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

package lang

import (
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// FindAllPointers returns all the pointers that point to v.
func FindAllPointers(res *pointer.Result, v ssa.Value) []pointer.Pointer {
	var allptr []pointer.Pointer
	if ptr, ptrExists := res.Queries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	// By indirect query
	if ptr, ptrExists := res.IndirectQueries[v]; ptrExists {
		allptr = append(allptr, ptr)
	}
	return allptr
}

// FindTransitivePointers adds all transitive pointers of v to ptrs.
func FindTransitivePointers(ptrRes *pointer.Result, reachable map[*ssa.Function]bool, v ssa.Value) []pointer.Pointer {
	stack := FindAllPointers(ptrRes, v)
	seen := make(map[pointer.Pointer]struct{})
	var res []pointer.Pointer
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		for _, label := range cur.PointsTo().Labels() {
			val := label.Value()
			if val == nil || val.Parent() == nil {
				continue
			}

			ptrs := FindAllPointers(ptrRes, val)
			stack = append(stack, ptrs...)
			for _, ptr := range ptrs {
				res = append(res, ptr)
			}
		}
	}

	return res
}

// FindAllMayAliases populates aliases with all the values that may-alias ptr.
func FindAllMayAliases(res *pointer.Result, reachable map[*ssa.Function]bool, allValues map[ssa.Value]struct{}, ptr pointer.Pointer, aliases map[ssa.Value]struct{}) {
	for val := range allValues {
		if _, ok := aliases[val]; ok {
			continue
		}

		ptrs := FindTransitivePointers(res, reachable, val)
		for _, valPtr := range ptrs {
			if valPtr.MayAlias(ptr) {
				aliases[val] = struct{}{}
			}
		}
	}
}

// ReachableFrom returns the functions reachable from from
// according to cg.
func ReachableFrom(cg *callgraph.Graph, from *ssa.Function, filter func(*ssa.Function) bool) map[*ssa.Function]bool {
	var nodes []*callgraph.Node
	for f, node := range cg.Nodes {
		if f == from {
			nodes = append(nodes, node)
		}
	}

	return reachable(cg, nodes, filter)
}

// CallGraphReachable returns a map where each entry is a reachable function
func CallGraphReachable(cg *callgraph.Graph, excludeMain bool, excludeInit bool) map[*ssa.Function]bool {
	entryPoints := findCallgraphEntryPoints(cg, excludeMain, excludeInit)
	return reachable(cg, entryPoints, func(*ssa.Function) bool { return false })
}

func reachable(cg *callgraph.Graph, entryPoints []*callgraph.Node, filter func(*ssa.Function) bool) map[*ssa.Function]bool {
	reachable := make(map[*ssa.Function]bool, len(cg.Nodes))
	frontier := make([]*callgraph.Node, 0)
	for _, node := range entryPoints {
		//	node := cg.Root
		reachable[node.Func] = true
		frontier = append(frontier, node)
	}

	for len(frontier) != 0 {
		node := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, edge := range node.Out {
			if filter(edge.Callee.Func) {
				continue
			}
			if !reachable[edge.Callee.Func] {
				reachable[edge.Callee.Func] = true
				frontier = append(frontier, edge.Callee)
			}
		}
	}
	return reachable
}

func findCallgraphEntryPoints(cg *callgraph.Graph, excludeMain bool, excludeInit bool) []*callgraph.Node {
	entryPoints := make([]*callgraph.Node, 0)
	for f, node := range cg.Nodes {

		if (!excludeMain && f.Name() == "main" && f.Pkg != nil && f.Pkg.Pkg.Name() == "main") ||
			(!excludeInit && f.Name() == "init" && f.Pkg != nil && f.Pkg.Pkg.Name() == "main") {
			entryPoints = append(entryPoints, node)
		}
	}
	return entryPoints
}
