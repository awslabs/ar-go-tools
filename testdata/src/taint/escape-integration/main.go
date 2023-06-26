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
	"math/rand"
	"sync"
)

func sink1(s string) {
	fmt.Printf("Sink: %s\n", s)
}

func source1() string {
	return fmt.Sprintf("<tainted:%d>", rand.Int())
}

type A struct {
	field1 string
	field2 int
}

type Node struct {
	next  *Node
	label string
}

func source2() A {
	return A{
		field1: fmt.Sprintf("<tainted:%d>", rand.Int()),
		field2: rand.Int(),
	}
}

func ResetAndCallSink(x *string) {
	*x = "ok"
	sink1(*x) // @Sink(ex1p1) @Escape(ex1p1) (with concurrency, ex1p2 should also reach)
}

func Set(x *string) {
	*x = source1() // @Source(set)
}

func ExampleEscape1() {
	x := source1() // @Source(ex1p1)
	go ResetAndCallSink(&x)
	x = x + source1() // @Source(ex1p2) @Escape(ex1p1)
}

func ResetAndCallSink2(x *string) {
	*x = "ok"
	sink1(*x) // @Sink(ex1p1bis) @Escape(ex1p1bis)
}

func ExampleEscape1bis() {
	x := source1() // @Source(ex1p1bis)
	ResetAndCallSink2(&x)
	x = x + source1() // @Source(ex1p2bis)
}

func ExampleEscape2() {
	y := source2()  // @Source(ex2)
	sink1(y.field1) // @Sink(ex2)
}

func ExampleEscape3() {
	x := source1() // @Source(ex3)
	a := &A{field1: x, field2: 0}
	sink1(a.field1) // @Sink(ex3)
	go ex3foo(x)    // no escape: only a value is passed to ex3foo
}

func ex3foo(s string) {
	s += "ok"
	fmt.Println(s)
}

func ExampleEscape4() {
	x := source1() // @Source(ex4)
	a := &A{field1: x, field2: 0}
	sink1(a.field1) // @Sink(ex4)
	go ex4foo(&x)
}

func ex4foo(s *string) {
	*s += "ok"      // @Escape(ex4)
	fmt.Println(*s) // @Escape(ex4)
}

func ExampleEscape5() {
	x := source1() // @Source(ex5)
	a := &A{field1: x, field2: 0}
	sink1(a.field1) // @Sink(ex5)
	c := make(chan string)
	go func() { c <- x }() // value sent
	go ex5foo(c)
}

func ex5foo(c chan string) {
	for s := range c {
		sink1(s) // @Sink(ex5)
	}
}

func ExampleEscape6() {
	x := source1() // @Source(ex6)
	a := &A{field1: x, field2: 0}
	sink1(a.field1) // @Sink(ex6)
	c := make(chan *string)
	go ex6send(c, &x)
	go ex6foo(c)
}

func ex6send(c chan *string, x *string) {
	c <- x // @Escape(ex6, ex6bis)
}

func ex6foo(c chan *string) {
	for s := range c {
		sink1(*s) // @Sink(ex6) , but not ex6bis! However, alarm is raised in ex6send
	}
}

func ExampleEscape6bis() {
	x := source1() // @Source(ex6bis)
	c := make(chan *string)
	go ex6foo(c)
	go ex6send(c, &x)
}

var G = Node{nil, "g"}

func ExampleEscapeRecursion() {
	var mu sync.Mutex
	mu.Lock()
	G.label = source1() // @Source(simpleRec) @Escape(simpleRec)
	go func() {
		G.label = source1()
		mu.Unlock()
	}()
	mu.Lock()
	x := &Node{&Node{&G, "2"}, "1"}
	c := recursiveConcat(x)
	sink1(c) // @Sink(simpleRec)
}

func recursiveConcat(n *Node) string {
	if n == nil {
		return ""
	}
	r := n.label                 // @Escape(simpleRec)
	r += recursiveConcat(n.next) // @Escape(simpleRec)
	return r
}

func ExampleEscapeMutualRecursion() {
	var mu sync.Mutex
	mu.Lock()
	G.label = source1() // @Source(mutualRec) @Escape(mutualRec)
	go func() {
		G.label = source1()
		mu.Unlock()
	}()
	mu.Lock()
	x := &Node{&Node{&Node{&G, "3"}, "2"}, "1"}
	c := recConcat1(x)
	sink1(c) // @Sink(mutualRec)
}

func recConcat1(n *Node) string {
	if n == nil {
		return ""
	}
	r := n.label            // @Escape(mutualRec)
	r += recConcat2(n.next) // @Escape(mutualRec)
	return r
}

func recConcat2(n *Node) string {
	if n == nil {
		return ""
	}
	r := n.label            // @Escape(mutualRec)
	r += recConcat1(n.next) // @Escape(mutualRec)
	return r
}

func main() {
	ExampleEscape1()
	ExampleEscape1bis()
	ExampleEscape2()
	ExampleEscape3()
	ExampleEscape4()
	ExampleEscape5()
	ExampleEscape6()
	ExampleEscape6bis()
	ExampleEscapeRecursion()
	ExampleEscapeMutualRecursion()
}
