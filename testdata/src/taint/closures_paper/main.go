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

// Package main contains examples that are adapted from the paper: "Lifting on-demand analysis to higher-order languages"
// https://www.amazon.science/publications/lifting-on-demand-analysis-to-higher-order-languages
package main

func process(getData func() string, handle func(...string)) {
	data := getData()
	handle(data) // @Sink(ex1, ex2)
}

// example1 has the source function called in a closure supplied to process.
func example1() {
	handler := sink
	process(func() string { return source() }, handler) // @Source(ex1)
	process(func() string { return "ok" }, handler)
}

// example2 has the source function passed as an argument to process.
// This tests the analysis' ability to handle source function entrypoints in function arguments.
func example2() {
	handler := sink
	process(source, handler) // @Source(ex2)
	process(func() string { return "ok" }, handler)
}

func main() {
	example1()
	example2()
}
