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

func main() {
	ExampleEscape6()
}
