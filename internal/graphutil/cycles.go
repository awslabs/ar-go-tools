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
	"sort"

	"github.com/yourbasic/graph"
)

// FindAllElementaryCycles finds all elementary cycles in the graph CGraph
// This uses Donald B. Johnson's algorithm presented in
// "Finding All The Elementary Circuits of a Directed Graph", 1975
//
//	cg : the graph with cycles
func FindAllElementaryCycles(cg CGraph) [][]int64 {
	s := &state{
		blocked: map[int64]bool{},
		blist:   map[int64]map[int64]bool{},
		stack:   []int64{},
		cycles:  [][]int64{},
	}
	nodeid := 0
	for nodeid < len(cg.Keys) {
		fg := Subgraph(cg, cg.Keys[nodeid:])
		components := graph.StrongComponents(fg)
		foundC2 := false
		for _, component := range components {
			if len(component) >= 2 {
				foundC2 = true
				sort.Slice(component, func(i, j int) bool { return component[i] < component[j] })
				node := component[0]
				nodeid = node
				s.stack = []int64{}
				s.blocked = map[int64]bool{}
				s.blist = map[int64]map[int64]bool{}
				s.circuit(int64(node), int64(node), fg)
				nodeid++
			}
		}
		if !foundC2 {
			return s.cycles
		}
	}
	return s.cycles
}

type state struct {
	blocked map[int64]bool
	blist   map[int64]map[int64]bool
	stack   []int64
	cycles  [][]int64
}

func (s *state) unblock(u int64) {
	s.blocked[u] = false
	for w := range s.blist[u] {
		if s.blocked[w] {
			s.unblock(w)
		}
	}
}

func (s *state) circuit(v int64, i int64, g CGraph) bool {
	f := false
	s.stack = append(s.stack, v)
	s.blocked[v] = true
	for w := range g.Edges[v] {
		if w == i {
			stackCopy := make([]int64, len(s.stack))
			copy(stackCopy, s.stack)
			stackCopy = append(stackCopy, w)
			s.cycles = append(s.cycles, stackCopy)
			f = true
		} else if !s.blocked[w] {
			if s.circuit(w, i, g) {
				f = true
			}
		}
	}

	if f {
		s.unblock(v)
	} else {
		for w := range g.Edges[v] {
			m := s.blist[w]
			if m != nil {
				s.blist[w][v] = true
			} else {
				s.blist[w] = map[int64]bool{v: true}
			}
		}
	}
	s.stack = s.stack[:len(s.stack)-1]
	return f
}
