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

type DataHolder interface {
	GetData() string
}

type TaintedHolder struct {
	data string
}

func (t TaintedHolder) GetData() string {
	return t.data
}

type CleanHolder struct {
	data string
}

func (c CleanHolder) GetData() string {
	return c.data
}

func processWithAssertion(x interface{}) {
	if holder, ok := x.(DataHolder); ok {
		sink(holder.GetData()) // @Sink(assertion1)
	}
}

func processWithAssertion2(x interface{}) {
	if holder, ok := x.(DataHolder); ok {
		sink(holder.GetData())
	}
}

func processWithDirectAssertion(x interface{}) {
	holder := x.(DataHolder) // panic if not DataHolder
	sink(holder.GetData())   // @Sink(assertion2)
}

func processStringAssertion(x interface{}) {
	if s, ok := x.(string); ok {
		sink(s) // @Sink(assertion3)
	}
}

func testAssertions() {
	tainted := TaintedHolder{data: source()} // @Source(assertion1)
	clean := CleanHolder{data: "clean"}
	taintedStr := source() // @Source(assertion3)

	processWithAssertion(tainted) // should reach sink
	processWithAssertion2(clean)  // should not reach sink

	processWithDirectAssertion(TaintedHolder{data: source()}) // @Source(assertion2)

	processStringAssertion(taintedStr) // should reach sink inside that function
}
