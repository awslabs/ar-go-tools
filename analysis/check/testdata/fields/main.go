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

// twoFields is used to test that a flow between two distinct fields of the same parameter
// (c.Src -> c.Dst below) is not mistaken for a self-flow.
type twoFields struct {
	Src int
	Dst int
}

// copyFieldToOther flows c.Src into c.Dst: same underlying parameter node (c), but two
// distinct fields. This is not a self-flow (Src != Dst) and must not be filtered out by the
// redundant-self-flow check in summaryFlows.
func copyFieldToOther(c *twoFields) {
	c.Dst = c.Src
}

func testCopyFieldToOther() {
	x := &twoFields{Src: 1, Dst: 0}
	copyFieldToOther(x)
	fmt.Printf("x.Dst:%v\n", x.Dst)
}

// nestedTwoFields is used to test the interaction between the self-flow filter and the
// subsumption filter (a -> b implies a.f -> b.f) in the same summaryFlows call: a summary can
// declare a true self-flow (Src -> Src) alongside a coarse/fine pair on Src -> Dst that should
// be filtered by subsumption, without either filter interfering with the other.
type nestedTwoFields struct {
	Src inner
	Dst inner
}

type inner struct {
	X int
}

func copyNestedFieldToOther(c *nestedTwoFields) {
	c.Dst = c.Src
}

func testCopyNestedFieldToOther() {
	x := &nestedTwoFields{Src: inner{X: 1}, Dst: inner{X: 0}}
	copyNestedFieldToOther(x)
	fmt.Printf("x.Dst:%v\n", x.Dst)
}

func readNestedFieldValue(c *nestedTwoFields) int {
	return c.Src.X
}

func testReadNestedFieldValue() {
	x := &nestedTwoFields{Src: inner{X: 1}, Dst: inner{X: 0}}
	fmt.Println(readNestedFieldValue(x))
}

// readNestedFieldValueByVal is the by-value counterpart to readNestedFieldValue: c is a plain
// (non-pointer) parameter, so it never escapes and the pointer analysis has no points-to
// information for it. This tests whether checkReads' pth.len() > 1 fallback (which depends on
// pointer-analysis labels) produces a false "not read" for a value that has no points-to set at
// all, since only the pth.len() == 1 fast path is independent of pointer-analysis results.
func readNestedFieldValueByVal(c nestedTwoFields) int {
	return c.Src.X
}

func testReadNestedFieldValueByVal() {
	fmt.Println(readNestedFieldValueByVal(nestedTwoFields{Src: inner{X: 1}, Dst: inner{X: 0}}))
}

// readNestedFieldViaHelper reads c.Src.X via a helper function readInnerX, to test the
// inter-procedural case: fieldPathMatches must correctly bottom out at the callee's own
// parameter (not literal identity with the top-level val, which never holds across function
// boundaries) when checkReads' BFS descends into a callee.
func readInnerX(in *inner) int {
	return in.X
}

func readNestedFieldViaHelper(c *nestedTwoFields) int {
	return readInnerX(&c.Src)
}

func testReadNestedFieldViaHelper() {
	x := &nestedTwoFields{Src: inner{X: 1}, Dst: inner{X: 0}}
	fmt.Println(readNestedFieldViaHelper(x))
}

// writeNestedFieldOnly writes only c.Src.X, mirroring writeBodyOnly but for a 2-segment path.
func writeNestedFieldOnly(c *nestedTwoFields, v int) {
	c.Src.X = v
}

func testWriteNestedFieldOnly() {
	x := &nestedTwoFields{Src: inner{X: 1}, Dst: inner{X: 0}}
	writeNestedFieldOnly(x, 5)
	fmt.Println(x.Src.X)
}

// prefixSiblingFields is used to test that isCoveredBy does not mistake one field name being a
// string-prefix of another (e.g. "Body" is a string-prefix of "BodyStart") for one path
// containing the other: they are sibling fields, not nested. Mirrors aws-sdk-go's
// aws/request.Request, whose Body and BodyStart fields previously tripped this bug.
type prefixSiblingFields struct {
	Src       int
	Body      int
	BodyStart int
}

func copySrcToBodyAndBodyStart(c *prefixSiblingFields) {
	c.Body = c.Src
	c.BodyStart = c.Src
}

func testCopySrcToBodyAndBodyStart() {
	x := &prefixSiblingFields{Src: 1, Body: 0, BodyStart: 0}
	copySrcToBodyAndBodyStart(x)
	fmt.Printf("x.Body:%v x.BodyStart:%v\n", x.Body, x.BodyStart)
}

// writeBodyOnly is used to test that checkWritesPtr's field-path filtering correctly
// distinguishes writes to sibling fields whose names share a string prefix ("Body" is a
// string-prefix of "BodyStart"): writing to c.Body must not be misattributed as a write to
// c.BodyStart (or vice versa) by the immutability analysis.
func writeBodyOnly(c *prefixSiblingFields, v int) {
	c.Body = v
}

func testWriteBodyOnly() {
	x := &prefixSiblingFields{Src: 1, Body: 0, BodyStart: 0}
	writeBodyOnly(x, 5)
	fmt.Printf("x.Body:%v x.BodyStart:%v\n", x.Body, x.BodyStart)
}

// readFieldViaPointer is used to confirm that fieldAddrIsDereferenced still correctly detects a
// genuine read through a field address (as opposed to copySrcToBodyAndBodyStart above, where the
// field addresses are only ever used as write destinations).
type oneField struct {
	Val int
}

func readFieldViaPointer(c *oneField) int {
	p := &c.Val // *ssa.FieldAddr
	return *p   // *ssa.UnOp (MUL) dereferences p: this is a real read of c.Val
}

func testReadFieldViaPointer() {
	x := &oneField{Val: 1}
	fmt.Println(readFieldViaPointer(x))
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
	return &Pair{First: b.First, Second: y.Second}
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
	(*b).First = x.First + x.Second
	(*b).Second = y.Second + y.First
	return &Pair{First: x.First + y.First, Second: x.Second + y.Second}
}

func testThreeArgInterFieldsDiffCallees() {
	x := &Pair{First: 0, Second: 0}
	y := &Pair{First: 1, Second: 1}
	z := &Pair{First: 2, Second: 2}
	res := threeArgInterFieldsDiffCallees(x, y, z)
	fmt.Printf("res: %v\n", res)
}

func threeArgInterTree(a, b, no *tree) {
	mergeTreesLeft(a, b, no)
	mergeTreesRight(a, b, no)
}

func mergeTreesLeft(a, b, no *tree) {
	a.left.right = b.left.left
}

func mergeTreesRight(a, b, no *tree) {
	a.right.left = b.right.right
}

func testThreeArgInterTree() {
	a := &tree{n: 3, left: &tree{n: 2, left: &tree{n: 1}, right: &tree{n: 0}}}
	b := &tree{n: 3, right: &tree{n: 2, right: &tree{n: 1}, left: &tree{n: 0}}}
	no := &tree{}
	threeArgInterTree(a, b, no)
	fmt.Printf("a: %v\n", a)
}

func main() {
	testIncFieldBy()
	testIncRight()
	testAppendSliceLinkedList()
	testThreeArgInterFields()
	testThreeArgInterFieldsDiffCallees()
	testThreeArgInterTree()
	testCopyFieldToOther()
	testCopyNestedFieldToOther()
	testReadNestedFieldValue()
	testReadNestedFieldValueByVal()
	testReadNestedFieldViaHelper()
	testWriteNestedFieldOnly()
	testCopySrcToBodyAndBodyStart()
	testWriteBodyOnly()
	testReadFieldViaPointer()
}
