package main

import (
	"taint-tracking-inter/subpkg"
)

func test5() {
	s := source1() // @Source(example3)
	x := subpkg.Data{Field: s}
	callInterface(x)
}

func callInterface(a subpkg.A) {
	sink1(a.F()) // @Sink(example3)
}
