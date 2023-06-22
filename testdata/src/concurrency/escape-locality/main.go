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
	"sync"
)

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
	next  *Node
	value string
}

var globalVar *Node = nil

func main() {
	testLocality()
	testRecursion()
	failInterproceduralLocality1()
	testInterproceduralLocality1()
	failInterproceduralLocality2()
	testDiamond()
}

func testLocality() {
	x := &Node{}   // LOCAL
	x.next = nil   // LOCAL
	y := globalVar // NONLOCAL
	y.next = nil   // NONLOCAL
}

func accessLocal(n *Node) {
	n.value = "str" // LOCAL
}
func accessNonlocal(n *Node) {
	n.value = "str" // NONLOCAL
}
func accessBoth(n *Node) {
	n.value = "str" // BOTH
}

// This should fail the checks
func failInterproceduralLocality1() {
	n := &Node{}
	globalNode.next = n
	accessLocal(n)
}

func testInterproceduralLocality1() {
	n := &Node{}
	accessLocal(n)
}

func failInterproceduralLocality2() {
	n := &Node{}
	accessNonlocal(n)
}

func diamondLeft(n *Node) {
	accessBoth(n)
}
func diamondRight(n *Node) {
	accessBoth(n)
}
func testDiamond() {
	l := &Node{}
	r := &Node{}
	globalNode.next = r
	diamondLeft(l)
	diamondRight(r)
}

func source() string {
	return "G"
}
func sink(s string) {
	fmt.Printf("Sink: %v\n", s)
}

var globalNode Node = Node{nil, "g"}

func testRecursion() {
	// Lock to ensure program doesn't have a data race
	var mu sync.Mutex
	mu.Lock()
	go func() {
		globalNode.value = source()
		mu.Unlock()
	}()
	mu.Lock()
	x := &Node{&Node{&globalNode, "2"}, "1"}
	c := recursiveConcat(x)
	sink(c)
}

// In the context where it is called from testRecursion, the params are:
//
//	n --> Node{"1"} --> Node{"2"} --> global
//
// where n and both Nodes are local, and global is external.
// The first recursive call gives us:
//
//	n --> Node{"2"} --> global
//
// If we stop here and do not consider more contexts, we would conclude
// that n.value is always local, but n can refer to global, and thus the
// load n.value can be non-local.
func recursiveConcat(n *Node) string {
	if n == nil {
		return ""
	}
	r := n.value
	r += recursiveConcat(n.next)
	return r
}

func leak(p *string) {
	// pkgGlobal = p
}

// in standard library:
func notBad(x string, p *string) {
	*p = x
	leak(p)
}
func veryBad(x string, p *string) {
	y := "abc"
	q := &y
	*q = x
	leak(q)
}