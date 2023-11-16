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

func ExampleEscape1() {
	x := source1() // @Source(ex1p1)
	go ResetAndCallSink(&x)
	x = x + source1() // @Source(ex1p2) @Escape(ex1p2, ex1p1)
}

func ResetAndCallSink2(x *string) {
	*x = "ok"
	sink1(*x) // @Sink(ex1p1bis)
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
	go func() { c <- x }() // @Escape(ex5)
	go ex5foo(c)           // @Escape(ex5)
}

func ex5foo(c chan string) {
	for s := range c { // @Escape(ex5)
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
	for s := range c { //@Escape(ex6)
		sink1(*s) // @Sink(ex6) , but not ex6bis! However, alarm is raised in ex6send
	}
}

func ExampleEscape6bis() {
	x := source1() // @Source(ex6bis)
	c := make(chan *string)
	go ex6foo(c)
	go ex6send(c, &x)
}

func ExampleEscape7() {
	s := source1() // @Source(ex7)
	s2 := s + "ok"
	x := &Node{&Node{&Node{label: s2}, "2"}, "1"}
	ex7foo(x.next)
}

func ex7foo(n *Node) {
	if n == nil {
		return
	}
	n2 := n.next
	sink1(n2.label) // @Sink(ex7)
}

func ExampleEscape8() {
	s := source1() // @Source(ex8)
	s2 := s + "ok"
	x := &Node{&Node{&Node{label: s2}, "2"}, "1"}
	ex8foo(x.next)
}

func ex8foo(n *Node) {
	if n == nil {
		return
	}
	n2 := n.next
	go sink1(n2.label) // @Sink(ex8) + no escape, passing a value
}

func ExampleEscape9() {
	s := source1() // @Source(ex9)
	s2 := s + "ok"
	x := &Node{&Node{&Node{label: s2}, "2"}, "1"}
	ex9foo(x.next)
}

func ex9foo(n *Node) {
	if n == nil {
		return
	}
	n2 := n.next
	go ex9bar(n2)
	go ex9bar(n)
}

func ex9bar(n *Node) {
	sink1(n.label) // @Sink(ex9) @Escape(ex9)
}

func ExampleEscape10() {
	s := source1() // @Source(ex10)
	s2 := s + "ok"
	x := &Node{&Node{&Node{label: s2}, "2"}, "1"}
	ex10foo(x.next)
	s3 := source1() // @Source(ex10bis)
	y := &Node{&Node{&Node{label: s3}, "2"}, "1"}
	ex10fooBar(y)
}

func ex10foo(n *Node) {
	if n == nil {
		return
	}
	n2 := n.next
	go ex10bar(n2)
}

func ex10fooBar(n *Node) {
	if n == nil {
		return
	}
	n2 := n.next
	ex10bar(n2)
}

func ex10bar(n *Node) {
	// Context sensitivity test: ex10 and ex10bis flow here, but only ex10 escape because of ex10foo
	sink1(n.label) // @Sink(ex10, ex10bis) @Escape(ex10)
}

func ExampleEscape11() {
	s := source1() // @Source(ex11)
	s2 := s + "ok"
	a := make([]*Node, 10)
	x := &Node{label: s2}
	a[0] = &Node{label: "ok"}
	a[1] = &Node{label: "fine"}
	a[0].next = a[1]
	a[1].next = x // a[0] -> a[1] -> x (tainted)
	ex11foo(a)
}

func ex11foo(n []*Node) {
	if n == nil {
		return
	}
	n2 := n[0].next
	go ex11bar(n2)
	go ex11bar(n[1])
}

func ex11bar(n *Node) {
	sink1(n.label) // @Sink(ex11) @Escape(ex11)
}

func ExampleEscape12() {
	s := source1() // @Source(ex12)
	s2 := s + "ok"
	a := make([]*Node, 10)
	x := &Node{label: s2}
	a[0] = &Node{label: "ok"}
	a[1] = &Node{label: "fine"}
	a[0].next = a[1]
	a[1].next = x // a[0] -> a[1] -> x (tainted)
	ex12foo(a)
}

func ex12foo(n []*Node) {
	if n == nil {
		return
	}
	n2 := n[0].next
	go ex12bar(n2)
	go ex12Foobar(n)
}

func ex12bar(n *Node) {
	// Not a sink
	fmt.Printf("%s", n.label) // @Escape(ex12)
}

func ex12Foobar(n []*Node) {
	fmt.Println(n[0].label) // @Escape(ex12)
}

func ExampleEscape13() {
	s := source1() // @Source(ex13)
	s2 := s + "ok"
	a := make([]*Node, 10)
	x := &Node{label: "nice"}
	a[0] = &Node{label: "ok"}
	a[1] = &Node{label: "fine"}
	a[0].next = a[1]
	a[1].next = x
	go ex13foo(a)
	x.label = s2 // @Escape(ex13)
}

func ex13foo(n []*Node) {
	if n == nil {
		return
	}
	n2 := n[0].next
	go ex13bar(n2)
}

func ex13bar(n *Node) {
	fmt.Printf("%s", n.label) // The data from the source has not reach here, but an alarm is
	// raised where it has escaped.
}

func ExampleEscape14() {
	s := source1() //@Source(ex14)
	x := &Node{&Node{nil, "ok"}, "ok"}
	go ex14foo(x.next)
	if x.next.next != nil {
		x.next.next.label = s // @Escape(ex14)
	}
}

func ex14foo(n *Node) {
	n.next = &Node{}
	sink1(n.next.label) // No escape here, since we don't know the source data flows here
	// However, an alarm is raised because the source is written to a location that has escaped!
}

func ExampleEscape15() {
	s := source1() //@Source(ex15)
	x := &Node{&Node{nil, "ok"}, "ok"}
	ex15foo(x.next) // x escapes
	if x.next.next != nil {
		x.next.next.label = s // @Escape(ex15) source is written to escaped value
	}
}

func ex15foo(n *Node) {
	n.next = &Node{}
	go ex15bar(n.next)
}

func ex15bar(n *Node) {
	sink1(n.next.label) // No escape here, since we don't know the source data flows here
	// However, an alarm is raised because the source is written to a location that has escaped!
}

var G = Node{nil, "g"}

func ExampleEscapeRecursion() {
	var mu sync.Mutex
	mu.Lock()
	G.label = source1() // @Source(simpleRec) @Escape(simpleRec)
	go func() {
		G.label = source1() // @Source(simpleRec2) @Escape(simpleRec2)
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
		G.label = source1() // @Source(mutualRec2) @Escape(mutualRec2)
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
	r := n.label            // @ Escape(mutualRec) #TODO Recursion
	r += recConcat2(n.next) // @ Escape(mutualRec) #TODO Recursion
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

func ExampleUnsummarizedFunction() {
	s := source1() // @Source(ext)
	t := "untainted"
	otherFunction1(s, t)
}

// The defintion of otherFunction1 is hidden from the escape analysis, but not taint
func otherFunction1(s string, t string) {
	n := &Node{}
	otherFunction2(s, t, n)
}

func otherFunction2(s string, t string, n *Node) {
	// Here, s is tainted, and n is local, but the escape analysis does not see the definition of
	// otherFunction1, so it assumes n is escaped
	n.label = s // @Escape(ext)
	n2 := &Node{}
	n2.label = t
	G.next = n2 // no escape should happen, as t is untainted
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
	ExampleEscape7()
	ExampleEscape8()
	ExampleEscape9()
	ExampleEscape10()
	ExampleEscape11()
	ExampleEscape12()
	ExampleEscape13()
	ExampleEscape14()
	ExampleEscape15()
	ExampleEscapeRecursion()
	ExampleEscapeMutualRecursion()
	ExampleUnsummarizedFunction()
}
