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

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

type intGraph map[int][]int

func isToposorted(m intGraph, sccs [][]int) error {
	covered := map[int]bool{}
	for i, scc := range sccs {
		for _, x := range scc {
			// Ensure every node from the graph appears at most once
			if covered[x] {
				return fmt.Errorf("repeated value %v\nin:%v", x, m)
			}
			covered[x] = true
			// Ensure that every x reaches every other y of the SCC.
			// This ensures it is strongly connected, but not necessarily maximal.
			for _, y := range scc {
				if x != y && !reaches(m, x, y) {
					return fmt.Errorf("the SCC nodes are not reachable: %v %v\nin:%v", x, y, m)
				}
			}
			for j := i + 1; j < len(sccs); j++ {
				for _, y := range sccs[j] {
					if reaches(m, x, y) {
						return fmt.Errorf("node %v appears before reachable node %v\nin:%v", x, y, m)
					}
				}
			}
		}
	}
	for n := range m {
		// Ensure every node appears at least once. Combined with above, ensures it appears
		// exactly once
		if !covered[n] {
			return fmt.Errorf("missing node %v\nin:%v", n, m)
		}
	}
	return nil
}
func TestSCC(t *testing.T) {
	assertResultIsToposorted := func(m intGraph) {
		sccs := StronglyConnectedComponents(nodesOf(m), succFunc(m))
		if err := isToposorted(m, sccs); err != nil {
			t.Fatalf("Error: %v", err)
		}
	}
	assertResultIsToposorted(intGraph{
		0: {0},
	})
	assertResultIsToposorted(intGraph{
		0: {},
	})

	assertResultIsToposorted(intGraph{
		0: {0, 1},
		1: {},
	})
	assertResultIsToposorted(intGraph{
		0: {1, 2},
		1: {3},
		2: {1},
		3: {},
	})
	assertResultIsToposorted(intGraph{
		0: {1, 2},
		1: {3},
		2: {1, 0},
		3: {},
	})
	assertResultIsToposorted(intGraph{
		0: {3, 1},
		1: {0},
		2: {1},
		3: {3},
	})
	// Doe some random tests
	for i := 0; i < 100; i++ {
		assertResultIsToposorted(randomGraph(10, 68348438+int64(i)))
	}
	for i := 0; i < 10; i++ {
		assertResultIsToposorted(randomGraph(50, 184618+int64(i)))
	}
	for i := 0; i < 3; i++ {
		assertResultIsToposorted(randomGraph(100, 4875934+int64(i)))
	}
}

func randomGraph(size int, seed int64) intGraph {
	m := map[int][]int{}
	r := rand.New(rand.NewSource(seed))
	for i := 0; i < size; i++ {
		m[i] = []int{}
		for j := 0; j < 3; j++ {
			if r.Float32() < 0.7 {
				m[i] = append(m[i], int(r.Int63()%int64(size)))
			}
		}
	}
	return m
}

// Computes whether y is reachable from x
func reaches(m map[int][]int, x, y int) bool {
	visited := map[int]bool{}
	var visit func(int)
	visit = func(n int) {
		if visited[n] {
			return
		}
		visited[n] = true
		for _, nn := range m[n] {
			visit(nn)
		}
	}
	visit(x)
	return visited[y]
}

// Return sorted nodes of a particular map
func nodesOf(m map[int][]int) []int {
	ks := []int{}
	for k := range m {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	return ks
}

// Returns a closure which gives the successors of a node, to satisfy the SCC API
func succFunc(m map[int][]int) func(int) []int {
	return func(k int) []int { return m[k] }
}
