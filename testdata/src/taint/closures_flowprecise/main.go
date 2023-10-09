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
	"strconv"
)

// example1: in this example, a function (example1RunStringGetter) takes as argument a function and call the function
// to obtain a string and then returns a string.
// With precise handling of closures through their flow, we are able to differentiate what is returned between the two
// cals of example1RunStringGetter, because we have a complete stack trace when the function a is called

type E1 struct {
	Data  string
	Index int
}

func example1RunStringGetter(stringGetter func() string) string {
	return stringGetter()
}

func example1tainter(s *E1) {
	s.Index = 0
	v := &s.Data
	*v = source() // @Source(ex1)
}

func example1() {
	data := &E1{Data: "ok", Index: 10}
	a := func() string { return fmt.Sprintf("%s", data.Data) }
	b := func() string { return "fine" }
	example1tainter(data)
	x1 := example1RunStringGetter(a)
	x2 := example1RunStringGetter(b)
	sink(x1) //@Sink(ex1)
	sink(x2)
}

// example2: a variation of example1 with slightly more complexity
func example2RunStringGetter(stringGetter func() string) string {
	return stringGetter()
}

func example2tainter(s *E1) {
	s.Index = 0
	v := &s.Data
	*v = source() // @Source(ex2)
}

func example2() {
	data := &E1{Data: "ok", Index: 10}
	a := func() string { return fmt.Sprintf("%s", data.Data) }
	b := func() string { return "fine" }
	c := func() string { return fmt.Sprintf("Calling a: %s", a()) }
	example2tainter(data)
	x1 := example2RunStringGetter(a)
	x2 := example2RunStringGetter(b)
	x3 := example2RunStringGetter(c)
	sink(x1) //@Sink(ex2)
	sink(x2)
	sink(x3) //@Sink(ex2)
}

// example3: mapping

func Map[T any, R any](a []T, f func(T) R) []R {
	res := make([]R, len(a))
	for i, x := range a {
		res[i] = f(x)
	}
	return res
}

func example3() {
	a := make([]string, 10)
	for i := range a {
		a[i] = "a-" + strconv.Itoa(i)
	}
	x := Map(a, func(s string) E1 {
		return E1{
			Data:  s,
			Index: 0,
		}
	})
	sink(x[0].Data) // @Sink(ex3) TODO: improve precision, flow was not used here
	y := Map(a, func(s string) E1 {
		return E1{
			Data:  s + source(), //@Source(ex3)
			Index: 0,
		}
	})
	sink(y[0].Data) // @Sink(ex3)
}

func MapX[T any, R any](a []T, f func(T) R) []R {
	res := make([]R, len(a))
	for i, x := range a {
		res[i] = f(x)
	}
	return res
}

func example3bis() {
	a := make([]string, 10)
	for i := range a {
		a[i] = "a-" + strconv.Itoa(i)
	}
	x := MapX(a, func(s string) E1 {
		return E1{
			Data:  s,
			Index: 0,
		}
	})
	sink(x[0].Data)
	appendix := source() //@Source(ex3bis)
	f := func(s string) E1 {
		return E1{
			Data:  s + appendix,
			Index: 0,
		}
	}
	y := MapX(a, f)
	sink(y[0].Data) // @Sink(ex3bis)
}

func main() {
	example1()
	example2()
	example3()
	example3bis()
}
