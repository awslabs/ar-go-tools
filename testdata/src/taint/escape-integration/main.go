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
	"time"
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

func source2() A {
	return A{
		field1: fmt.Sprintf("<tainted:%d>", rand.Int()),
		field2: rand.Int(),
	}
}

func ResetAndCallSink(x *string) {
	*x = "ok"
	sink1(*x) // @Sink(ex1p1)
}

func Set(x *string) {
	*x = source1() // @Source(set)
}

func ExampleEscape1() {
	x := source1() // @Source(ex1p1)
	go ResetAndCallSink(&x)
	x = x + source1() // @Source(ex1p2)
}

func ExampleEscape2() {
	y := source2() // @Source(ex2)
	sink1(y.field1)
}

func main() {
	ExampleEscape1()
	time.Sleep(100000)
}
