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

func TestMin() {
	f1 := source3() // @Source(min1)
	f2 := source3() // @Source(min2)
	c := min(f1, f2)
	sink(c) // @Sink(min1, min2)
}

func TestMax() {
	f1 := source3() // @Source(max1)
	f2 := source3() // @Source(max2)
	c := max(f1, f2)
	sink(c) // @Sink(max1, max2)
}

func TestClear() {
	m := make(map[string]string, 10)
	m["x"] = source1().Data //@Source(clear)
	clear(m)
	sink(m["a"]) //@Sink(clear) even though m is cleared, taint analysis cannot track that and over-approximates
}

func main() {
	TestMin()
	TestMax()
	TestClear()
}
