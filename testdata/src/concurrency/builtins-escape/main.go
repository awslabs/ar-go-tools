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

// This function represents a non-deterministic result. Because the analysis
// isn't boolean sensitive, we don't have to do anything fancy here.
func arbitrary() bool { return false }

// This is a no-op, but calls are checked by the test harness to check
// the set of edges from x and y are the same (i.e. they have the SameAliases).
func assertSameAliases(x, y any) {}

// Same, but asserts that all edges are to nodes that have leaked
func assertAllLeaked(x any) {}

// Same, but asserts all pointees are local (not escaped or leaked)
func assertAllLocal(x any) {}

type Node struct {
	next *Node
}

var globalVar *Node = nil

func main() {
	testMethod()
	testVarargs()
	testNilArg()
	testVariousBuiltins()
	testGo()
	testAppend([]*Node{})
	testIndexArray()
	testChannel()
	testChannelEscape()
	testSelect()
	testConvertStringToSlice()
}

func (n *Node) loopMethod(iters int) *Node {
	for {
		nn := n.next
		if nn != nil {
			n = nn
		} else {
			return n
		}
	}
}
func (n *Node) setNext(next *Node) {
	n.next = next
}

type SetNextable interface {
	setNext(next *Node)
}

type myError struct{ error }

func testMethod() {
	x := &Node{nil}
	y := x.loopMethod(0)
	assertSameAliases(x, y)

	x.setNext(x)
	assertSameAliases(x, x.next)
	var z SetNextable = x
	z.setNext(x)

	var err myError
	err.Error()
}

func printlike(fmt string, args ...string) {

}
func testVarargs() {
	// printlike("hi")
	printlike("one %s", "a")
	printlike("two %s %s", "a", "b")
}

func funcOfNode(n *Node) {

}
func funcOfNodeReturningNode(n *Node) *Node {
	return n
}
func testNilArg() {
	funcOfNode(nil)
	var x *Node
	assertSameAliases(nil, x)
}

func testGo() {
	x := &Node{}
	go funcOfNode(x)
	assertAllLeaked(x)
	y := &Node{}
	go funcOfNodeReturningNode(y) // check returning a pointer-like (should be like `_ := f()`)
	assertAllLeaked(y)

}
func testVariousBuiltins() int {
	x := make([]int, 5)
	l := len(x)

	return l
}

func testAppend(s []*Node) []*Node {
	s = append(s, &Node{})
	return s
}

var globalArray = [...]*Node{
	nil, nil, nil,
}

func testIndexArray() {
	x := &Node{}
	y := &Node{}
	arr := [2]*Node{x, y}
	z := arr[0]
	w := y
	if arbitrary() {
		w = x
	}
	assertSameAliases(z, w)
	a := &globalArray[0]
	assertAllLeaked(a)
}
func recv(ch chan *Node) *Node {
	return <-ch
}
func testChannel() {
	x := &Node{}
	ch := make(chan *Node, 1)
	ch <- x
	y := recv(ch)
	assertSameAliases(x, y)
	assertAllLocal(x)
	assertAllLocal(ch)
}

func testChannelEscape() {
	x := &Node{}
	ch := make(chan *Node, 1)
	ch <- x
	go recv(ch)
	assertAllLeaked(x)
}

func testSelect() {

	x := &Node{}
	y := &Node{}
	ch := make(chan *Node, 1)
	select {
	case ch <- x:

	case ch <- y:

	}
	w := x
	if arbitrary() {
		w = y
	}
	select {
	case z := <-ch:
		assertSameAliases(z, w)
		assertAllLocal(z)
	default:

	}
}

func testConvertStringToSlice() {
	x := "abc"
	y := []byte(x)
	assertAllLocal(y)
	z := []rune(x)
	assertAllLocal(z)
	w := x[:]
	assertAllLocal(w)
}
