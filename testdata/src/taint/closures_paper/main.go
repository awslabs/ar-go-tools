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
	data := getData() // @Source(ex2 call:example2->call:process->call:example2$1, ex3 call:example3->call:process->call:example3$3)
	handle(data)      // @Sink(ex1, ex2, ex3)
}

// example1 has the source function called in a closure supplied to process.
func example1() {
	handler := sink
	process(func() string { return source() }, handler) // @Source(ex1 call:example1->call:process->call:example1$1->call:source)
	process(func() string { return "ok" }, handler)
}

// example2 has the source function passed as an argument to process.
// This tests the analysis' ability to handle source function entrypoints in function arguments.
func example2() {
	handler := sink
	process(source, handler)
	process(func() string { return "ok" }, handler)
}

// example3 has the same output as the previous two examples but the source function is returned
// from another function and passed to process.
// The handler and s functions modify a free variable to prevent inlining.
func example3() {
	str := "hello"
	handler := func() func(...string) {
		str += "world"
		return sink
	}
	s := func() func() string {
		str += " "
		return source
	}
	process(s(), handler())
	process(func() string { return "ok" }, handler())
	_ = str // technically not needed but may prevent an unused variable warning in the future
}

func main() {
	example1()
	example2()
	example3()
}
