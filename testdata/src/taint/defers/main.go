package main

import "fmt"

type A struct {
	Field string
}

func sink(x string) {
	fmt.Println(x)
}

func callsSink(a A) {
	sink(a.Field)
}

func callsSinkRef(a *A) {
	sink(a.Field) // @Sink(source)
}

func source() A {
	return A{Field: "bad"}
}

func taintMe(a *A) {
	*a = source() // @Source(source)
}

func main() {
	a := A{"ok"}
	b := &A{"ok"}
	defer callsSink(a)    // does not raise alarm
	defer callsSinkRef(b) // will raise alarm
	a = source()
	taintMe(b)
	testPart2()
}

func testPart2() {
	a := A{Field: "ok"}
	functionWithDeferredSink(a)
}

func functionWithDeferredSink(a A) {
	x := "stringContent"
	s := &x
	defer sink(*s) // does not raise alarm
	taintMe(&a)
	*s = a.Field
}
