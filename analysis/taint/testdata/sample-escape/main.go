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

type a struct {
	field1 string
	field2 int
}

type Node struct {
	next  *Node
	label string
}

func main() {
	s := source1() // @Source(main)
	x := &Node{&Node{nil, "ok"}, "ok"}
	go ex14foo(x.next)
	if x.next.next != nil {
		x.next.next.label = s // @Escape(main)
	}
}

func ex14foo(n *Node) {
	n.next = &Node{}
	sink1(n.next.label) // No escape here, since we don't know the source data flows here
	// However, an alarm is raised because the source is written to a location that has escaped!
}
