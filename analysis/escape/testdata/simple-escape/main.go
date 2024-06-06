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

var globalS *S = nil

func main() {
	testAddrOfGlobal()
	testGlobalLoadStore()
	consume(globalS)
	loop(buildList())
	testMapValue()
	testMapKey()
	leakThroughGlobal()
	testFieldOfGlobal()
	testSlice()
	testManyAccesses(nil)
}

func testAddrOfGlobal() {
	x := &globalS
	y := &Sptr{}
	y.S = x
}
func consume(s *S) {
	globalS = s
}

func testGlobalLoadStore() *S {
	v := &S{1, nil}
	v.Bptr = &B{3.24}
	globalS = v
	v = globalS
	return v
}
func leakThroughGlobal() {
	s := &S{}
	globalS = s
}

func testMapValue() *S {
	m := map[int]*S{}

	m[0] = &S{}
	m[0].Bptr = &B{1.0}
	return m[0]
}
func testMapKey() *S {
	m := map[*S]int{}

	x := &S{}
	m[x] = 4
	for y := range m {
		return y
	}
	return nil
}
func testSlice() *S {
	x := &S{}
	y := &S{}
	slice := []*S{x, y}
	return slice[1]
}

var GG S

func testFieldOfGlobal() {
	x := &GG.Bptr
	*x = &B{324}
}

type Node struct {
	next *Node
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
func buildList() *Node {
	var n *Node = nil
	for i := 0; i < 10; i++ {
		n = &Node{n}
	}
	return n
}

type B struct {
	F float32 `json:"f"`
}
type S struct {
	I    int `json:"i"`
	Bptr *B  `json:"x"`
}
type Sptr struct {
	S **S
}

func testManyAccesses(n *Node) {
	// this creates a lot of load operations, which should result in  just one load node
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
	_ = n.next
}
