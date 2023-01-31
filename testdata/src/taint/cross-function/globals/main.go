package main

import "test-globals/foo"

// TestTaintPropagatesThroughGlobal
var x T

func TestTaintPropagatesThroughGlobal() {
	a := source1() // @Source(ex1)
	runX(a)
	sink(x) // @Sink(ex1)
}

func runX(s T) {
	x = s
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

func main() {
	taintGlobalDoesNotFollowDataFlow()
	TestTaintPropagatesThroughGlobal()
	TestTaintDoesNotFollowDataflow()
	TestTaintGlobalThroughClosure()
	TestTaintGlobalFromSlice()
	TestTaintPropagatesThroughPackageGlobal()
}
