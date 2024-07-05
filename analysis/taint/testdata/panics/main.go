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

// This tests that flows created by defers are sound, when a panic from a function call
// changes the program point that defers are run in.

// The first test just makes sure that flows in defers are

package main

import "fmt"

func source() string {
	return "123"
}
func sink(a string) {
	fmt.Printf("Sink %v\n", a)
}

type Obj struct {
	f string
}

// Look at a flow through a field, written in a defer, without panics
func nopanictest(x *Obj, b string) {
	defer func() {
		x.f = b
	}()
	return
}

func main1() {
	x := &Obj{}
	b := source() // @Source(defer1)
	nopanictest(x, b)
	sink(x.f) // @Sink(defer1)
}

func bar() {
	panic("whatever")
}

func panictest(x *Obj, b string) {
	defer func() {
		x.f = b
	}()
	bar()   // always panics here, and so defer is executed
	b = "0" // clears taint from b, but never executed
	return
}

func catchPanic(x *Obj, b string) {
	defer func() { recover() }()
	panictest(x, b)
}

func main2() {
	x := &Obj{}
	b := source() // @Source(panicReorder)
	catchPanic(x, b)
	sink(x.f) // @Sink(panicReorder)
}

func main() {
	main1()
	main2()
}
