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

import "fmt"

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
	testAlias()
	inverseAlias()
	inverseLeaked()
	inverseLocal()
	inverseLocalEscapedOnly(&Node{})
	testTraverseList()
	testTraverseListRecur()
	testStepLargeList()
	testMultiReturnValues()
	testConsume()
	testFresh()
	testIdent()
	testExternal()
	testChain()
}

// Basic test of the assertSameAliases function
func testAlias() {
	x := &Node{nil}
	assertSameAliases(x, x) // This should succeed
}

// Meta-test that the assertSameAliases function does the right thing
// functions that do not start with test succeed if they raise an error
func inverseAlias() {
	x := &Node{nil}
	y := &Node{nil}
	assertSameAliases(x, y) // This should fail
}

// Meta-test that the assertAllLeaked function checks for leaks
func inverseLeaked() {
	x := &Node{nil}
	assertAllLeaked(x) // This should fail
}

// Meta-test that the assertAllLocal function fails on leaked nodes
func inverseLocal() {
	x := &Node{nil}
	globalVar = x
	assertAllLocal(x) // This should fail
}

// Meta-test that the assertAllLocal function fails on escaped but not leaked nodes
func inverseLocalEscapedOnly(x *Node) {
	assertAllLocal(x) // This should fail
}

func loop(n *Node) *Node {
	for {
		nn := n.next
		if nn != nil {
			n = nn
		} else {
			return n
		}
	}
}

// Test that a loop function will give the only node in a linked list of size 1
func testTraverseList() *Node {
	x := &Node{nil}
	y := loop(x)
	assertSameAliases(x, y)
	return y
}

func loopRecur(n *Node) *Node {
	nn := n.next
	if nn != nil {
		return loopRecur(nn)
	} else {
		return n
	}
}

// Test the invocation of a recursive function
func testTraverseListRecur() *Node {
	x := &Node{&Node{}}
	y := loopRecur(x)
	z := x
	if arbitrary() {
		z = z.next
	}
	assertSameAliases(y, z) // z = x or x.next
	return y
}

func oneStep(n *Node) *Node {
	return n.next
}

// Tests that multiple function calls compose together, and also that field lookups work correctly
func testStepLargeList() *Node {
	x0 := &Node{nil}
	x1 := &Node{x0}
	x2 := &Node{x1}
	y := oneStep(oneStep(x2))
	assertSameAliases(y, x0)
	assertSameAliases(x0, x2.next.next)
	return y
}

func nodeAndNext(n *Node) (*Node, *Node) {
	return n, n.next
}

// This test is disabled until we support tuple-sensitivity
func testMultiReturnValues() *Node {
	x := &Node{nil}
	y := &Node{x}
	_, b := nodeAndNext(y)
	// assertSameAliases(x, b)
	return b
}

func identity(n *Node) *Node {
	return n
}

// Test that the summary of the identity function correctly returns its argumen
func testIdent() *Node {
	x := &Node{nil}
	y := identity(x)
	assertSameAliases(x, y)
	return y
}

func fresh() *Node {
	x := &Node{nil}
	assertAllLocal(x)
	return x
}

// Test that a function that allocates an object produces a local object
func testFresh() *Node {
	x := fresh()
	assertAllLocal(x)
	return x
}

func consume(n *Node) {
	globalVar = n
}

// Tests that calling a function that leaks propagates into the caller
func testConsume() *Node {
	x := &Node{}
	consume(x)
	assertAllLeaked(x)
	return x
}

// Test that a call to an external function leaks its arguments.
// Due to the way printf works this also tests slices
func testExternal() error {
	x := &Node{}
	_, err := fmt.Printf("Value: %v\n", x)
	assertAllLeaked(x)
	return err
}

func chainExtend(a *Node, b *Node) {
	a.next.next.next = b
}
func chainExtendWrapper(a *Node, b *Node) {
	chainExtend(a, b)
}
func testChain() {
	a := &Node{&Node{&Node{}}}
	b := &Node{}
	chainExtendWrapper(a, b)
	globalVar = a
	assertAllLeaked(b)
}
