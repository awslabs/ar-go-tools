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

// StronglyConnectedComponents is an implementation of Tarjan's strongly connected component (SCC) algorithm
// for generic nodes T.
// Successors returns a slice containing the targets of directed edges out from the given node.
// sccs is a slice of slices containing the nodes in each SCC. The order within the SCC is arbitrary.
// The order of SCCs is toposorted so that successors appear first; i.e. if the graph is a tree then
// in order from leaves towards the root. For summary-based bottom-up algorithms, the result is in
// the desired order to minimize recomputation.
func StronglyConnectedComponents[T comparable](nodes []T, successors func(T) []T) (sccs [][]T) {
	stack := make([]T, 0)
	onStack := make(map[T]bool, 0)
	index := make(map[T]int, 0)
	lowlink := make(map[T]int, 0)
	nextIndex := 0
	sccs = make([][]T, 0)

	var visit func(v T)

	visit = func(v T) {
		index[v] = nextIndex
		lowlink[v] = nextIndex
		stack = append(stack, v)
		onStack[v] = true
		nextIndex++
		for _, w := range successors(v) {
			if _, ok := index[w]; !ok {
				visit(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if index[w] < lowlink[v] {
					lowlink[v] = index[w]
				}
			}
		}
		if lowlink[v] == index[v] {
			scc := make([]T, 0)
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}
	for _, v := range nodes {
		if _, ok := index[v]; !ok {
			visit(v)
		}
	}
	return sccs
}
