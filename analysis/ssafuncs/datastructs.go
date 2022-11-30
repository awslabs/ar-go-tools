package ssafuncs

import "golang.org/x/tools/go/ssa"

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

// IsRoot returns true is the node is a leaf (i.e. no Parent)
func (t *BlockTree) IsRoot() bool {
	return t.Parent == nil
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
