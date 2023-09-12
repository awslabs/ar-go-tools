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

func wrap(a string, before string, after string) string {
	return fmt.Sprintf("%s%s%s", before, a, after)
}

func sink(a ...string) {
	for _, x := range a {
		println(x)
	}
}

func source() string {
	return "-tainted-"
}

type Ex14 struct {
	Count  int
	Lambda func(int, string) string
}

func (e Ex14) Run(s string, i int) string {
	e.Count += i
	return e.Lambda(e.Count, s)
}

func NewEx14() *Ex14 {
	data := source() // @Source(ex14)
	e := &Ex14{
		Count: 0,
		Lambda: func(i int, s string) string {
			return strconv.Itoa(i) + s + data
		},
	}
	return e
}

func callSink14(run func(string) string, s string) {
	sink(run(s)) // @Sink(ex14)
}

func example14() {
	e := NewEx14()
	f := func(s string, i int) string { return e.Run(s, i) }
	callSink14(func(s string) string { return f(s, 1) }, "ok")
}

func main() {
	example14()
}
