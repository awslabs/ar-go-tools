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

func Validate(x string) bool {
	return x != "sensitive-data"
}

func gen(s *string) {
	*s = source1() // @Source(gen)
}

// Example 0: validator used a condition before calling sink

func validatorExample0() {
	x := source1() // @Source(ex0)
	if Validate(x) {
		sink1(x) // This has been validated!
	} else {
		sink1(x) // @Sink(ex0)
	}
}

func validatorExample0Bis() {
	var x string
	gen(&x)
	value := x // this is necessary to make sure the value validated is "owned"
	if Validate(value) {
		sink1(value) // This has been validated!
	} else {
		sink1(value) // @Sink(gen)
	}
}

func validatorExample0BisNegative() {
	var x string
	gen(&x)
	if Validate(x) { // x is loaded first then validated as a value
		sink1(x) // @Sink(gen) // this is not validated because the SSA needs to load x again here
	} else {
		sink1(x) // @Sink(gen)
	}
}

// Example 1: validator is used to clear value inside a conditional

func validatorExample1() {
	s := "ok"
	gen(&s)
	k := ""
	if rand.Int() > 10 {
		k = s
	} else {
		if !Validate(s) {
			k = ""
		}
	}
	sink1(k) // @Sink(gen) TODO: false alarm, but this is acceptable for now
}

// Example 2: validator is used to return before sink if negative

func validatorExample2() {
	s := "ok"
	gen(&s)
	if !Validate(s) {
		return
	}
	sink1(s) // @Sink(gen) TODO: normalize conditions to identify validator usages
}

// Example 3: validator is used to assign value only when safe

func validatorExample3() {
	s := "ok"
	gen(&s)
	k := ""
	if Validate(s) {
		k = s
	}
	sink1(k) // @Sink(gen) TODO: flow sensitivity with variable reinitialized
}

// Example 4: validator is used inside a function being called

func pass(i int, x string) (bool, string) {
	r := strings.Clone(x) + strconv.Itoa(i)
	return Validate(r), r
}

func validatorExample4() {
	a := source1() // @Source(ex4)
	ok, b := pass(2, a)
	if ok {
		sink1(b) // @Sink(ex4) TODO: validators on part of the argument
	}
}

// Example 5: every element of a slice is validated

func validatorExample5() {
	a := make([]string, 10)
	for i := range a {
		a[i] = source1() // @Source(ex5)
	}
	b := make([]string, 10)
	for i := range b {
		if Validate(a[i]) {
			b[i] = a[i]
		}
	}
	sink1(b[0]) // @Sink(ex5) TODO: flow sensitivity
}

// Example 6: validate an entire struct when a field is tainted

type A struct {
	X int
	Y string
}

func Validate2(a A) bool {
	return a.X > 0 && Validate(a.Y)
}

func validatorExample6() {
	a1 := A{
		X: len(source1()), // @Source(ex6f1)
		Y: source1(),      // @Source(ex6f2)
	}
	sink1(strconv.Itoa(a1.X)) // @Sink(ex6f1,ex6f2)
	if Validate2(a1) {
		i, _ := strconv.Atoi(a1.Y)
		sink1(i) // @Sink(ex6f1,ex6f2) TODO: do we need flow-sensitive validation?
	}
}

func main() {
	validatorExample0()
	validatorExample0Bis()
	validatorExample0BisNegative()
	validatorExample1()
	validatorExample2()
	validatorExample3()
	validatorExample4()
	validatorExample5()
	validatorExample6()
}