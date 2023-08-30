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
)

func wrap(a string, before string, after string) string {
	return fmt.Sprintf("%s%s%s", before, a, after)
}

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
	*v = source() // @Source(ex18)
}

func example1() {
	data := &E1{Data: "ok", Index: 10}
	a := func() string { return fmt.Sprintf("%s", data.Data) }
	b := func() string { return "fine" }
	example1tainter(data)
	x1 := example1RunStringGetter(a)
	x2 := example1RunStringGetter(b)
	sink(x1) //@Sink(ex18)
	sink(x2)
}

func main() {
	example1()
}
