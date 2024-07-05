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
	"encoding/json"
	"fmt"
	"reflect"
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

// Asserts has at least one non-nil pointee
func assertNotNil(x any) {}

type Node struct {
	next *Node
}

var globalVar *Node = nil

func main() {
	testPrintf()
	// testLeakingPrintfThroughStringMethod() // TODO: This requires support in the pointer analysis
	testReflect()
	testBasicUnmarshal()
	testBasicUnmarshalLeak()
	testUnmarshalIntoAny()
	testCustomUnmarshal()
	testCustomUnmarshalAliasing()
	testBasicMarshal()
	testCustomMarshal()
}

func testPrintf() {
	x := &Node{}
	fmt.Printf("Node is %v\n", x)
	assertAllLeaked(x) // TODO: FIXME !
}

type LeakerThroughString struct {
	a *Node
	b *Node
}

func (l *LeakerThroughString) String() {
	l.a.next = l.b
}
func testLeakingPrintfThroughStringMethod() {
	a, b := &Node{}, &Node{}
	globalVar.next = a
	t := &LeakerThroughString{a, b}
	assertAllLocal(b)
	fmt.Printf("Node is %v\n", t)
	assertAllLeaked(b)
}

func testReflect() {
	x := &Node{}
	v := reflect.ValueOf(x)
	assertAllLocal(x)
	y := v.Interface().(*Node)
	assertSameAliases(x, y)
}

type Simple struct {
	S string
	X *Simple
}

func testBasicUnmarshal() {
	x := &Simple{}
	json.Unmarshal([]byte("{}"), x)
	assertAllLocal(x)
	assertAllLocal(x.X)
}

var globalSimpleStruct *Simple

func testBasicUnmarshalLeak() {
	x := &Simple{}
	json.Unmarshal([]byte("{\"X\":{}}"), x)
	y := x.X
	assertNotNil(y)
	z := &Simple{}
	y.X = z
	globalSimpleStruct = y
	assertAllLeaked(z)
}

func testUnmarshalIntoAny() {
	var x any
	json.Unmarshal([]byte("{\"X\":{}}"), &x)
	m := x.(map[string]any)["X"].(map[string]any)
	n := &Node{}
	m["Y"] = n
	globalVar.next = m["Y"].(*Node)
	assertAllLeaked(n)
}

type StructCustomUnmarshal struct {
	a *Node
	b *Node
}

func (s *StructCustomUnmarshal) UnmarshalJSON(data []byte) error {
	s.a = &Node{}
	s.b = &Node{}
	return nil
}
func testCustomUnmarshal() {
	x := &StructCustomUnmarshal{}
	json.Unmarshal([]byte("{}"), x)
	globalVar.next = x.b
	assertAllLeaked(x.b)
	assertNotNil(x.a)
	assertNotNil(x.b)
}

type StructCustomUnmarshalAliasing struct {
	data []byte
}

func (s *StructCustomUnmarshalAliasing) UnmarshalJSON(data []byte) error {
	s.data = data
	return nil
}

func testCustomUnmarshalAliasing() {
	x := &StructCustomUnmarshalAliasing{}
	slice := []byte("{}")
	json.Unmarshal(slice, x)
	assertSameAliases(slice, x.data)
}

func testBasicMarshal() {
	x := &Simple{}
	json.Marshal(x)
	assertAllLocal(x)
}

type StructCustomMarshal struct {
	a *Node
	b *Node
}

func (s *StructCustomMarshal) MarshalJSON() (data []byte, e error) {
	s.b = s.a
	s.a = s.b
	return []byte{}, nil
}
func testCustomMarshal() {
	a := &Node{}
	b := &Node{}
	x := &StructCustomMarshal{a, b}
	var _ json.Marshaler = x
	json.Marshal(x)
	assertSameAliases(x.a, x.b)
}
