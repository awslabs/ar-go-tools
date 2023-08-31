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

//go:build go1.21

package main

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
)

func TestMapDeleteFunc() {
	m := map[string]int{
		"one":          1,
		"two":          2,
		"three":        3,
		"four":         4,
		source1().Data: 4, //@Source(mapDeleteFunc)
	}
	maps.DeleteFunc(m, func(k string, v int) bool {
		sink2(v) //@Sink(mapDeleteFunc)
		sink1(k) //@Sink(mapDeleteFunc)
		return len(k) > 3
	})
	fmt.Println(m)
}

func TestMapEqual() {
	m := map[string]int{
		"one":          1,
		"two":          2,
		"three":        3,
		"four":         4,
		source1().Data: 4, //@Source(mapEqual)
	}
	m2 := map[string]int{
		"one":   1,
		"two":   2,
		"three": 3,
		"four":  4,
	}
	b := maps.Equal(m, m2)
	if b {
		sink2(m2["four"]) // Using equal doesn't taint the other operand
	}
}

func TestMapEqualFunc() {
	m := map[string]int{
		"one":          1,
		"two":          2,
		"three":        3,
		"four":         4,
		source1().Data: 4, //@Source(mapEqual)
	}
	m2 := map[string]int{
		"one":   1,
		"two":   2,
		"three": 3,
		"four":  4,
	}
	b := maps.EqualFunc(m, m2, func(x int, y int) bool {
		sink2(x) // @Sink(mapEqual)
		return x > y+3
	})
	if b {
		sink2(m2["four"]) // Using equal doesn't taint the other operand
	}
}

func TestMapCopy() {
	m := map[string]string{
		"one":   "a",
		"two":   "b",
		"three": "c",
		"four":  "d",
		"five":  source1().Data, //@Source(mapCopy)
	}
	m2 := make(map[string]string)
	maps.Copy(m2, m)
	sink1(m2["five"]) //@Sink(mapCopy)
}

func TestMapCopy2() {
	m := map[string]string{
		"one":   "a",
		"two":   "b",
		"three": "c",
		"four":  "d",
		"five":  source1().Data, //@Source(mapCopy2)
	}
	m2 := make(map[string]string)
	maps.Copy(m, m2)
	sink1(m2["five"]) // not tainted, wrong copy direction
}

func TestMapClone() {
	m := map[string]string{
		"one":   "a",
		"two":   "b",
		"three": "c",
		"four":  "d",
		"five":  source1().Data, //@Source(mapClone)
	}
	m2 := maps.Clone(m)
	sink1(m2["five"]) // @Sink(mapClone)
}

func TestCmpCompare() {
	x := source1() // @Source(cmpCompare)
	y := T{"data", "ok"}
	res := cmp.Compare(x.Data, y.Other)
	sink2(res) // cmp.Compare doesn't return the data, the data is only used in the control flow
}

func TestCmpLess() {
	x := source1() // @Source(cmpLess)
	y := T{"data", "ok"}
	res := cmp.Less(x.Data, y.Other)
	sink2(res) // @Sink(cmpLess) however, Less returns a value with an expression that involved the data directly
	// even though semantically this is almost the same as compare, the difference in implementation causes differences
	// in data flows. User can consider providing summaries to control that behaviour, e.g.:
	// {
	//    "ObjectPath" : "cmp",
	//    "Methods" : {"Less" : {"Args":[[0],[1]], "Rets": [[],[]] }}
	// }
	// This specification would make Less not return tainted data.
}

func TestBinarySearch() {
	names := []string{"x", "y", source3()} // @Source(binarySearch)
	n1, found := slices.BinarySearch(names, "y")
	if found {
		sink2(n1) //@Sink(binarySearch)
	}
	n2, found := slices.BinarySearch(names, "z")
	if found {
		sink2(n2) //@Sink(binarySearch)
	}
}

func main() {
	TestMapDeleteFunc()
	TestMapEqual()
	TestMapEqualFunc()
	TestMapCopy()
	TestMapCopy2()
	TestMapClone()
	TestCmpCompare()
	TestCmpLess()
	TestBinarySearch()
}
