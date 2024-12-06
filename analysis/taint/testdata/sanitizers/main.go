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
	"strconv"
	"strings"
)

func source1() string {
	return "sensitive-data"
}

func sink1(s any) {
	fmt.Println(s)
}

func Sanitize(x string) string {
	return x
}

func gen(s *string) {
	*s = source1() // @Source(gen)
}

// Example 0: sanitizer used directly on the output of the source

func sanitizerExample0() {
	sink1(Sanitize(source1()))
}

// Example 1: sanitizer is used inside a conditional

func sanitizerExample1() {
	s := "ok"
	gen(&s)
	k := ""
	if rand.Int() > 10 {
		k = s
	} else {
		k = Sanitize(s) // Obvious bad use of sanitizer
	}
	sink1(k) // @Sink(gen)
}

// Example 2: sanitizer is used and returns a string value

func sanitizerExample2() {
	s := "ok"
	gen(&s)
	k := Sanitize(s) // Good use of a sanitizer
	sink1(k)
}

// Example 3: sanitizer modifies value. The analysis is not dataflow sensitive and detects a flow

func sanitizerExample3() {
	s := "ok"
	gen(&s)
	s = Sanitize(s) // bad use of a sanitizer to reassign a value
	sink1(s)        // @Sink(gen)
}

// Example 4: sanitizer is used inside a function being called

func pass(i int, x string) string {
	r := strings.Clone(x) + strconv.Itoa(i)
	return Sanitize(r)
}

func sanitizerExample4() {
	a := source1() // @Source(ex4)
	b := pass(2, a)
	sink1(b)
}

// Example 5: every element of a slice is sanitized

func sanitizerExample5() {
	a := make([]string, 10)
	for i := range a {
		a[i] = source1() // @Source(ex5)
	}
	b := make([]string, 10)
	for i := range b {
		b[i] = Sanitize(a[i])
	}
	sink1(b[0])
}

// Example 6: sanitize an entire struct when a field is tainted

type A struct {
	X int
	Y string
}

func Sanitize2(a A) A {
	return A{a.X, a.Y}
}

func sanitizerExample6() {
	a1 := A{
		X: len(source1()), // len is a sanitizer
		Y: source1(),      // @Source(ex6f2)
	}
	sink1(strconv.Itoa(a1.X))
	a2 := Sanitize2(a1)
	i, _ := strconv.Atoi(a2.Y)
	sink1(i)
}

func sanitizerExampleLen() {
	x := len(source1()) // len is a sanitizer
	sink1(strconv.Itoa(x))
}

func main() {
	sanitizerExample0()
	sanitizerExample1()
	sanitizerExample2()
	sanitizerExample3()
	sanitizerExample4()
	sanitizerExample5()
	sanitizerExample6()
	sanitizerExampleLen()
}
