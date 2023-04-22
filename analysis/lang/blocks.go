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

import "golang.org/x/tools/go/ssa"

// HasPathTo returns true if there is a control-flow path from b1 to b2. Use mem to amortize cost. If mem is nil,
// then the algorithm runs without memoization, and no map is allocated.
func HasPathTo(b1 *ssa.BasicBlock, b2 *ssa.BasicBlock, mem map[*ssa.BasicBlock]map[*ssa.BasicBlock]bool) bool {
	if mem != nil {
		if _, ok := mem[b1]; !ok {
			mem[b1] = map[*ssa.BasicBlock]bool{}
		}
		if val, ok := mem[b1][b2]; ok {
			return val
		}
	}
	vis := map[*ssa.BasicBlock]bool{}
	que := []*ssa.BasicBlock{b1}
	for len(que) > 0 {
		cur := que[0]
		if cur == b2 {
			if mem != nil {
				mem[b1][b2] = true
			}
			return true
		}
		if mem != nil && mem[cur] != nil && mem[cur][b2] {
			mem[b1][b2] = true
			return true
		}
		vis[cur] = true
		que = que[1:]
		for _, nb := range cur.Succs {
			if !vis[nb] {
				que = append(que, nb)
			}
		}
	}
	if mem != nil {
		mem[b1][b2] = false
	}
	return false
}
