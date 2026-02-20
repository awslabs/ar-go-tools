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

package main

import (
	"fmt"
)

type simpleContainer struct {
	field data
}

type data struct {
	value int
}

func incFieldBy(c *simpleContainer, n int) {
	c.field.value += n
}

func testIncFieldBy() {
	x := &simpleContainer{field: data{0}}
	incFieldBy(x, 5)
	fmt.Printf("x.field:%v\n", x.field.value)
}

type container struct {
	field *data
	other *data
}

type tree struct {
	n     int
	right *tree
	left  *tree
}

func incRight(t tree, n int) {
	t.right.n += n
}

func testIncRight() {
	x := tree{n: 1, right: &tree{}, left: nil}
	fmt.Println("x.right:", x.right.n)
	// x.right: 2
	incRight(x, 2)
	fmt.Println("x.right:", x.right.n)
	// x.right: 2
}

type sliceLinkedList struct {
	value []string
	next  *sliceLinkedList
}

func appendSliceLinkedList(head *sliceLinkedList, n string) {
	current := head
	for current.next != nil {
		current = current.next
	}
	current.next = &sliceLinkedList{value: []string{n}, next: nil}
}

func testAppendSliceLinkedList() {
	lst := &sliceLinkedList{value: []string{"hello"}, next: nil}
	appendSliceLinkedList(lst, " world")
	fmt.Println(lst.next.value) // world
}

// Field-sensitive versions of threeArgInter tests

type Pair struct {
	First  int
	Second int
}

// Caller that flows to specific fields
func threeArgInterFields(no, a, b *Pair) *Pair {
	x := addPairFirst(*a, *a, no)
	y := addPairFirst(*a, *b, no)
	(*b).First = x.First + y.First
	return &Pair{First: b.First}
}

func testThreeArgInterFields() {
	x := &Pair{First: 0, Second: 0}
	y := &Pair{First: 1, Second: 1}
	z := &Pair{First: 2, Second: 2}
	res := threeArgInterFields(x, y, z)
	fmt.Printf("res: %v\n", res)
}

func addPairFirst(a, b Pair, no *Pair) Pair {
	b.First = a.First + b.First
	return Pair{First: b.First}
}

func addPairSecond(a, b Pair, no *Pair) Pair {
	b.Second = a.Second + b.Second
	return b
}

func threeArgInterFieldsDiffCallees(no, a, b *Pair) *Pair {
	x := addPairFirst(*a, *a, no)
	y := addPairSecond(*a, *b, no)
	(*b).First = x.First + y.First
	(*b).Second = x.Second + y.Second
	return &Pair{First: x.First, Second: y.Second}
}

func testThreeArgInterFieldsDiffCallees() {
	x := &Pair{First: 0, Second: 0}
	y := &Pair{First: 1, Second: 1}
	z := &Pair{First: 2, Second: 2}
	res := threeArgInterFieldsDiffCallees(x, y, z)
	fmt.Printf("res: %v\n", res)
}

func main() {
	testIncFieldBy()
	testIncRight()
	testAppendSliceLinkedList()
	testThreeArgInterFields()
	testThreeArgInterFieldsDiffCallees()
}
