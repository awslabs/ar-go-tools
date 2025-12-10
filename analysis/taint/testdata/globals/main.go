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
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/globals/foo"
)

// TestTaintPropagatesThroughGlobal
var x T
var globalSource1 T      // @Source(ex8)
var globalSource2 string // @Source(ex9)
var globalSource3 *T

func TestTaintPropagatesThroughGlobal() {
	a := source1() // @Source(ex1)
	runX(a)
	sink(x) // @Sink(ex1)
}

func runX(s T) {
	x = s
}

// Testing taint propagation through aliasing a global
var myGlobal *T

func TestTaintPropagatesThroughAliasingGlobal() {
	myAlias := myGlobal
	notSink(myAlias)
	*myAlias = source1() // @Source(ex11)
	sink(*myGlobal)      // @Sink(ex11)
}

// TestTaintDoesNotFollowDataflow
var y T

func TestTaintDoesNotFollowDataflow() {
	a := source1() // @Source(ex2)
	s := T{}
	runY(s)
	sink(y) // @Sink(ex2) --> This because when taint reaches a global, ALL locations are assumed tainted
	runY(a)
	sink(y) // @Sink(ex2)
}

func runY(s T) {
	y = s
}

func taintGlobalDoesNotFollowDataFlow() {
	sink(y) // @Sink(ex2)
}

// TestTaintGlobalThroughClosure

var z T

func TestTaintGlobalThroughClosure() {
	f := func() {
		z = source1() // @Source(ex3)
	}
	f()
	sink(z) // @Sink(ex3)
}

// TestTaintGlobalFromSlice
var za T

func TestTaintGlobalFromSlice() {
	a := []T{genT(), genT(), genT(), source1()} // @Source(ex4)
	for i, x := range a {
		if len(x.Data) > 3 {
			za = a[i]
		}
	}
	callSink(za)
}

func callSink(e T) {
	if e.Other == "ok" {
		sink(e) // @Sink(ex4)
	}
}

func TestTaintPropagatesThroughPackageGlobal() {
	x := source1() // @Source(ex5)
	foo.SetGlobal(x)
	foo.CallSink() // see call to sink in foo package
}

func TestReadGlobalIsTainted() {
	local := globalSource1 //@Source(ex6)
	//local := T{}
	sink(local.Data) // @Sink(ex6)
}

func TestGlobalAsArgIsTainted() {
	sink(globalSource1) // @Source(ex7) @Sink(ex7) global is loaded here
	sink(globalSource2) // @Source(ex7bis) @Sink(ex7bis)
}

func TestGlobalRefAsArgIsTainted() {
	sink(&globalSource1) // @Sink(ex8)
}

func TestGlobalRefAsArgIsTainted2() {
	sink(&globalSource2) // @Sink(ex9)
}

func TestGlobalAliasAsArgIsTainted() {
	local := globalSource3 // @Source(ex10)
	notSink(local)
	value := *local
	sinkStr(value.Data) // @Sink(ex10)
}

func main() {
	taintGlobalDoesNotFollowDataFlow()
	TestTaintPropagatesThroughGlobal()
	TestTaintPropagatesThroughAliasingGlobal()
	TestTaintDoesNotFollowDataflow()
	TestTaintGlobalThroughClosure()
	TestTaintGlobalFromSlice()
	TestTaintPropagatesThroughPackageGlobal()
	TestReadGlobalIsTainted()
	TestGlobalAsArgIsTainted()
	TestGlobalRefAsArgIsTainted()
	TestGlobalRefAsArgIsTainted2()
	TestGlobalAliasAsArgIsTainted()
}
