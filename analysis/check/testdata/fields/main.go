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

func propagateFieldsField(src, dst *container) {
	dst.field = &data{value: src.field.value + src.field.value}
}

func propagateFieldsOther(src, dst *container) {
	dst.other = &data{value: src.other.value + src.other.value}
}

func propagateFieldsBoth(src, dst *container) {
	dst.other = &data{value: src.field.value + src.other.value}
}

func addVals(a, b *data) *data {
	return &data{value: a.value + b.value}
}

func newx() *container {
	return &container{field: &data{0}, other: &data{1}}
}

func newy() *container {
	return &container{field: &data{2}, other: &data{2}}
}

func testFieldPropagationField() {
	x := newx()
	y := newy()
	propagateFieldsField(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
}

func testFieldPropagationOther() {
	x := &container{field: &data{0}, other: &data{1}}
	y := &container{field: &data{2}, other: &data{2}}
	propagateFieldsOther(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
}

func testFieldPropagationBoth() {
	x := &container{field: &data{0}, other: &data{1}}
	y := &container{field: &data{2}, other: &data{2}}
	propagateFieldsBoth(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
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
	return b
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
	return b
}

func addPairSecond(a, b Pair, no *Pair) Pair {
	b.Second = a.Second + b.Second
	return b
}

func threeArgInterFieldsDiffCallees(no, a, b *Pair) *Pair {
	x := addPairFirst(*a, *a, no)
	y := addPairSecond(*a, *b, no)
	(*b).Second = x.First + y.Second
	return b
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
	testFieldPropagationField()
	testFieldPropagationOther()
	testFieldPropagationBoth()
	testIncRight()
	testAppendSliceLinkedList()
	testThreeArgInterFields()
	testThreeArgInterFieldsDiffCallees()
}
