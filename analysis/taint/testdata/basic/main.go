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

func test0() {
	s := source1() // @Source(A)
	s1 := copyInput(s, 1)
	s3 := ""
	copyInto(s1, &s3)
	argReachesSink(s3)
}

func copyInput(s string, x int) string {
	if x > 1 {
		return s
	} else {
		return s
	}
}

func copyInto(s string, s2 *string) {
	*s2 = s
}

func sink1(s string) {
	fmt.Println(s)
}

func sink3(s any) {
	fmt.Println(s)
}

func argReachesSink(x string) {
	a := make([]string, 10)
	a[0] = "x"
	a[1] = "ok"
	a[2] = x
	sink1(a[2]) // want "reached by tainting call on line 6" @Sink(A)
}

func source1() string {
	return "tainted"
}

func main() {
	test0()
	test1()                       // see bar.go
	test2()                       // see example.go
	test3(10)                     // see example.go
	test4()                       // see example2.go
	test5()                       // see example3.go
	testField()                   // see fields.go
	testFieldEmbedded()           // see fields.go
	testStoreTaintedDataInField() // see fields.go
	testSourceFieldInSinkField()  // see fields.go
	testField2()                  // see fields.go
	runSanitizerExamples()        // see sanitizers.go
	testAliasingTransitive()      // see memory.go
	testChannelReadAsSource()     // see channels.go
	testValueMatch()              // see valuematch.go
}

type Data struct {
	Field string
}

type A interface {
	F() string
}

func (d Data) F() string {
	return d.Field
}

func (d Data) Sink(x string) {
	d.Field = x
}
