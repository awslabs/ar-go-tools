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
	"golang.org/x/tools/go/ssa/ssautil"
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
func FindTransitivePointers(res *pointer.Result, reachable map[*ssa.Function]bool, v ssa.Value, ptrs map[pointer.Pointer]struct{}) {
	stack := FindAllPointers(res, v)
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]
		if _, ok := ptrs[cur]; ok {
			continue
		}
		ptrs[cur] = struct{}{}

		for _, label := range cur.PointsTo().Labels() {
			val := label.Value()
			if val == nil || val.Parent() == nil {
				continue
			}
			if _, ok := reachable[val.Parent()]; !ok {
				// skip unreachable values
				continue
			}

			ptrs := FindAllPointers(res, val)
			stack = append(stack, ptrs...)
		}
	}
}

// AllValues returns all the values in prog.
func AllValues(prog *ssa.Program) map[ssa.Value]struct{} {
	vals := make(map[ssa.Value]struct{})
	fns := ssautil.AllFunctions(prog)
	for fn := range fns {
		IterateValues(fn, func(_ int, val ssa.Value) {
			vals[val] = struct{}{}
		})
	}

	return vals
}

// FindAllMayAliases populates aliases with all the values that may-alias ptr.
func FindAllMayAliases(res *pointer.Result, reachable map[*ssa.Function]bool, allValues map[ssa.Value]struct{}, ptr pointer.Pointer, aliases map[ssa.Value]struct{}) {
	for val := range allValues {
		if _, ok := aliases[val]; ok {
			continue
		}

		ptrs := make(map[pointer.Pointer]struct{})
		FindTransitivePointers(res, reachable, val, ptrs)
		for valPtr := range ptrs {
			if valPtr.MayAlias(ptr) {
				aliases[val] = struct{}{}
			}
		}
	}
}

// CallGraphReachable returns a map where each entry is a reachable function
func CallGraphReachable(cg *callgraph.Graph, excludeMain bool, excludeInit bool) map[*ssa.Function]bool {
	entryPoints := findCallgraphEntryPoints(cg, excludeMain, excludeInit)

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
