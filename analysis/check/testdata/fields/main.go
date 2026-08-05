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

// returnNestedByVal returns a whole nested struct field of a by-value parameter, so c.Src.X really
// does reach the return value's .X even though nothing in the body ever addresses X under Src.
// c is by value, so its spill slot does not escape and the pointer analysis has nothing to say
// about it either.
func returnNestedByVal(c nestedTwoFields, n int) inner {
	c.Dst.X = n
	return c.Src
}

func testReturnNestedByVal() {
	c := nestedTwoFields{Src: inner{X: 1}, Dst: inner{X: 2}}
	res := returnNestedByVal(c, 7)
	fmt.Println("testReturnNestedByVal", res.X) // 1
}

// returnArrayElemByVal returns a whole element of a by-value array, so a.Src.X really does reach the
// return value's .Src.X. Nothing in the body addresses X under Src, and the array is by value so its
// spill slot does not escape -- the same shape as returnNestedByVal, but reached through an index
// rather than a field.
func returnArrayElemByVal(a [2]nestedTwoFields, n int) nestedTwoFields {
	a[1].Dst.X = n
	return a[0]
}

func testReturnArrayElemByVal() {
	a := [2]nestedTwoFields{{Src: inner{X: 1}}, {Src: inner{X: 2}}}
	res := returnArrayElemByVal(a, 7)
	fmt.Println("testReturnArrayElemByVal", res.Src.X) // 1
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

// prefixSiblingFields is used to test that subsumes does not mistake one field name being a
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

// differentOutputDepths calls addPairFirst twice, reading one result at a field and using the other
// whole. calleeOutputPaths derives each call site's output precision from how the caller reads it, so
// the two sites get different access paths for the same callee output -- which is what
// buildCalleeSummaryConstrs has to relate when it forces both sites to infer one summary.
func differentOutputDepths(no, a, b *Pair) (int, Pair) {
	x := addPairFirst(*a, *a, no)
	y := addPairFirst(*b, *b, no)
	return x.First, y
}

func testDifferentOutputDepths() {
	a := &Pair{First: 1, Second: 2}
	b := &Pair{First: 3, Second: 4}
	no := &Pair{}
	n, p := differentOutputDepths(no, a, b)
	fmt.Println("testDifferentOutputDepths", n, p)
}

// sameArgDifferentOutputDepths calls addPairFirst twice with the same arguments, so both call sites
// receive their inputs at identical precision, and differ only in how deeply the *result* is read: one
// at .First, the other used whole. That isolates output-side precision, which calleeOutputDemand
// aggregates per callee output so both sites share one summary vocabulary.
func sameArgDifferentOutputDepths(no, a *Pair) (int, Pair) {
	x := addPairFirst(*a, *a, no)
	y := addPairFirst(*a, *a, no)
	return x.First, y
}

func testSameArgDifferentOutputDepths() {
	a := &Pair{First: 1, Second: 2}
	no := &Pair{}
	n, p := sameArgDifferentOutputDepths(no, a)
	fmt.Println("testSameArgDifferentOutputDepths", n, p)
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

// offsetReaderLike mirrors aws-sdk-go's request.Request.safeBody (an *offsetReader): an
// irrelevant sibling field that is itself a pointer to a multi-field struct, one level deeper
// than the relevant field being checked.
type offsetReaderLike struct {
	closed bool
	buf    string
}

// wideRequest mirrors aws-sdk-go's request.Request: a struct with a relevant field (body, the
// only one named in the checked "want" summary below) alongside an irrelevant sibling field
// (safeBody) that is itself a pointer to a further nested struct.
type wideRequest struct {
	body     string
	safeBody *offsetReaderLike
	err      error
}

// unmarshalLike mirrors aws-sdk-go's rest.unmarshalBody: it has no summary (so buildGraph must
// infer one), and only touches r.body/r.err, never r.safeBody -- but it is passed the whole *r,
// so buildGraph's fallback (no RelPath) must consider every field of r as a possible output,
// including safeBody and its own nested field(s).
func unmarshalLike(r *wideRequest) error {
	if r.body != "" {
		r.err = fmt.Errorf("got: %s", r.body)
	}
	return r.err
}

// requestUnmarshalLike mirrors aws-sdk-go's rest.Unmarshal: it calls the unsummarized
// unmarshalLike with the whole *r, even though the checked summary (see check_test.go) only
// cares about r.body flowing to r.err. r.safeBody is passed along as part of r but is never
// itself read or written by requestUnmarshalLike or unmarshalLike.
//
// This reproduces a scaling bug in buildGraph: r.safeBody (already collapsed to one path by
// inputNodes, since it's irrelevant to the checked summary) was still being expanded one level
// deeper via a redundant edge of the form r.safeBody -> (r as unmarshalLike's argument).safeBody,
// which is just r's own field flowing to itself through the call, carrying no information about
// what unmarshalLike does. This edge should be filtered out as a self-flow rather than requiring
// buildGraph to keep exploring one level deeper for every irrelevant field of r, however deeply
// nested its own type is.
func requestUnmarshalLike(r *wideRequest) error {
	return unmarshalLike(r)
}

func testRequestUnmarshalLike() {
	r := &wideRequest{body: "hello", safeBody: &offsetReaderLike{closed: false, buf: "x"}}
	fmt.Println(requestUnmarshalLike(r))
}

// siblingFields, writeSiblingField and siblingFieldViaCallee test whether the field-to-field
// blocking in mustNotFlowReachability is load-bearing. siblingFieldViaCallee has a real flow
// s.A -> s.B between two sibling fields of one parameter, realized inside a callee, and a second
// parameter t whose field-to-field flow makes any summary of siblingFieldViaCallee field-sensitive.
// A summary that declares only t.Src -> t.Dst omits s.A -> s.B and is therefore unsound; the
// question is whether the checker notices, given that s is named at no access path in that summary.
type siblingFields struct {
	A int
	B int
}

func writeSiblingField(s *siblingFields) {
	s.B = s.A
}

func siblingFieldViaCallee(s *siblingFields, t *twoFields) {
	writeSiblingField(s)
	t.Dst = t.Src
}

func testSiblingFieldViaCallee() {
	s := &siblingFields{A: 1, B: 0}
	t := &twoFields{Src: 2, Dst: 0}
	siblingFieldViaCallee(s, t)
	fmt.Printf("s.B:%v t.Dst:%v\n", s.B, t.Dst)
}

func main() {
	testIncFieldBy()
	testIncRight()
	testAppendSliceLinkedList()
	testThreeArgInterFields()
	testDifferentOutputDepths()
	testSameArgDifferentOutputDepths()
	testThreeArgInterFieldsDiffCallees()
	testThreeArgInterTree()
	testCopyFieldToOther()
	testCopyNestedFieldToOther()
	testReturnArrayElemByVal()
	testReturnNestedByVal()
	testReadNestedFieldValue()
	testReadNestedFieldValueByVal()
	testReadNestedFieldViaHelper()
	testWriteNestedFieldOnly()
	testCopySrcToBodyAndBodyStart()
	testWriteBodyOnly()
	testReadFieldViaPointer()
	testRequestUnmarshalLike()
	testSiblingFieldViaCallee()
}
