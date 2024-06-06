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

var global string

type A struct {
	x string
}

type B struct {
	Source string
}

func (a A) f(i string) string {
	return a.x + i
}

func Source() string {
	return "tainted"
}

func Sink(s string) {
	fmt.Println(s)
}

func Bar(x string) int {
	fmt.Println(x)
	return len(x)
}

func ChannelConsumer(c chan string) int {
	x := <-c
	Sink(x)
	return Bar(x)
}

func ChannelProducer(c chan string) {
	c <- Source()
}

func Foo(s string, s2 *string, obj A) int {
	a := make([]string, 10)
	a[0] = s
	for i := 1; i < 10; i++ {
		a[i] = a[i-1]
	}
	*s2 = obj.f(a[9])
	l := Bar(*s2)
	return l
}

func FooBar(x string) {
	s := B{Source: x}
	s2 := "ok"
	s3 := Foo(s.Source, &s2, A{})
	s4 := fmt.Sprintf("%s", s3)
	Sink(s4)
}

func Baz(x string) {
	s := B{Source: x}
	global = s.Source
	s1 := fmt.Sprintf("%s", global)
	Sink(s1)

	ok := "ok" // bound variable
	closure := func(s string) string {
		Sink(s1)
		s4 := fmt.Sprintf("%s", s)
		Sink(s4)
		return s + ok
	}
	s5 := closure(ok) // at this point, ok can only have been modified by the closure running
	ok = s.Source
	Sink(s5)
}

func ImplicitFlow() {
	s := Source()
	if len(s) == 0 {
		Sink("")
	}
}

func main() {
	s := fmt.Sprintf("bad-%s", "data")
	s2 := "example2"
	obj := A{x: "ex"}
	Foo(s, &s2, obj)
	FooBar("x")
	c := make(chan string, 10)
	c <- s2
	go ChannelProducer(c)
	go ChannelConsumer(c)
	x := Source()
	Baz(x)
	ImplicitFlow()
}
