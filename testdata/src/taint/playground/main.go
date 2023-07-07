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

func source() string {
	return "tainted"
}

func sink(s string) {
	fmt.Println(s)
}

// example11 is a case where a closure is assigned to a struct's field, and the closure is called later

type Ex11 struct {
	Count  int
	Lambda func(int, string) string
}

func (e Ex11) Run(s string) string {
	e.Count += 1
	return e.Lambda(e.Count, s)
}

func example11() {
	s1 := source() // @Source(ex11)
	e := Ex11{
		Count: 0,
		Lambda: func(i int, s string) string {
			return s1 + strconv.Itoa(i) + s
		},
	}

	f(&e)
}

func f(e *Ex11) {
	sink(e.Run("ok")) // @Sink(ex11)
}

// example12 is variation of example11

func NewEx11() *Ex11 {
	s1 := fmt.Sprintf("Ok")
	e := &Ex11{
		Count: 0,
		Lambda: func(i int, s string) string {
			return strconv.Itoa(i) + s + s1
		},
	}
	return e
}

func example12() {
	e := NewEx11()
	sink(e.Run("ok")) // @Sink(ex11) TODO: false positive here because Run is called and was tainted in ex11
}

func main() {
	example11()
	example12()
}
