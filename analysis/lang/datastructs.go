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

// BlockTree is a tree of ssa.BasicBlock
type BlockTree struct {
	Block    *ssa.BasicBlock
	Parent   *BlockTree
	Children []*BlockTree
}

// AddChild adds a child to t and returns pointer to that child
func (t *BlockTree) AddChild(block *ssa.BasicBlock) *BlockTree {
	newT := &BlockTree{Block: block, Parent: t, Children: []*BlockTree{}}
	t.Children = append(t.Children, newT)
	return newT
}

// CountPathOccurrences count how many times Block is encountered on the path to the root
func (t *BlockTree) CountPathOccurrences(block *ssa.BasicBlock) int {
	c := 0
	for cur := t; cur != nil; cur = cur.Parent {
		if cur.Block == block {
			c++
		}
	}
	return c
}

// A BlockPath is a simple list of blocks
type BlockPath struct {
	block *ssa.BasicBlock
	next  *BlockPath
}

// ToBlocks turns a pointer-based list into a slice
func (b *BlockPath) ToBlocks() []*ssa.BasicBlock {
	var blocks []*ssa.BasicBlock
	for cur := b; cur != nil; cur = cur.next {
		blocks = append(blocks, cur.block)
	}
	return blocks
}

// PathToLeaf returns the path from the root to the receiver
func (t *BlockTree) PathToLeaf() *BlockPath {
	if t == nil {
		return nil
	}

	p := &BlockPath{block: t.Block, next: nil}
	for leaf := t; leaf != nil; leaf = leaf.Parent {
		p2 := &BlockPath{block: leaf.Block, next: p}
		p = p2
	}
	return p
}
