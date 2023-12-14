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

import "github.com/awslabs/ar-go-tools/internal/funcutil"

// Tree is a simple generic implementation of a tree
type Tree[T any] struct {
	Parent   *Tree[T]
	Children []*Tree[T]
	Label    T
}

// NewTree returns a new tree with the labels of the type provided
func NewTree[T any](rootLabel T) *Tree[T] {
	return &Tree[T]{
		Parent:   nil,
		Children: nil,
		Label:    rootLabel,
	}
}

// Label returns the label of its argument
func Label[T any](t *Tree[T]) T {
	return t.Label
}

func (t *Tree[T]) AddChild(label T) *Tree[T] {
	newChild := &Tree[T]{
		Parent:   t,
		Children: nil,
		Label:    label,
	}
	if t.Children == nil {
		t.Children = []*Tree[T]{newChild}
	} else {
		t.Children = append(t.Children, newChild)
	}
	return newChild
}

// Ancestors returns the chain of the n closest ancestors of t. If n < 0, then it returns the chain up to the root
// of the tree
func (t *Tree[T]) Ancestors(n int) []*Tree[T] {
	var ans []*Tree[T]
	cur := t
	i := 0
	for cur != nil && (i < n || n < 0) {
		ans = append(ans, cur)
		cur = cur.Parent
		i++
	}
	funcutil.Reverse(ans)
	return ans
}
