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

package taint

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// TaintFlows is a map from instructions to sets of instructions. We use this to represents data flows: if there
// are two instructions sink,source such that map[sink][source], then there is a data flow from source to sink.
type TaintFlows = map[ssa.Instruction]map[ssa.Instruction]bool

// MergeTaintFlows merges its two input TaintFlows maps. When the function returns, the first argument contains
// all the entries in the second one.
// @requires a != nil
func MergeTaintFlows(a TaintFlows, b TaintFlows) {
	for x, yb := range b {
		ya, ina := a[x]
		if ina {
			a[x] = unionPaths(ya, yb)
		} else {
			a[x] = yb
		}
	}
}

// unionPaths is a utility function to merge two sets of instructions.
func unionPaths(p1 map[ssa.Instruction]bool, p2 map[ssa.Instruction]bool) map[ssa.Instruction]bool {
	for x, yb := range p2 {
		ya, ina := p1[x]
		if ina {
			p1[x] = yb || ya
		} else {
			p1[x] = yb
		}
	}
	return p1
}

// ReachedSinkPositions translated a DataFlows map in a program to a map from positions to set of positions,
// where the map associates sink positions to sets of source positions that reach it.
func ReachedSinkPositions(prog *ssa.Program, m TaintFlows) map[token.Position]map[token.Position]bool {
	positions := make(map[token.Position]map[token.Position]bool)

	for sinkNode, sourceNodes := range m {
		sinkPos := sinkNode.Pos()
		sinkFile := prog.Fset.File(sinkPos)
		if sinkPos != token.NoPos && sinkFile != nil {
			positions[sinkFile.Position(sinkPos)] = map[token.Position]bool{}
			for sourceNode := range sourceNodes {
				sourcePos := sourceNode.Pos()
				sourceFile := prog.Fset.File(sourcePos)
				if sinkPos != token.NoPos && sourceFile != nil {
					positions[sinkFile.Position(sinkPos)][sourceFile.Position(sourcePos)] = true
				}
			}
		}
	}
	return positions
}
