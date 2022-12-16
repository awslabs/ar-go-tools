package main

import "fmt"

type Interface interface {
	F() string
}

type A struct {
	Field string
}

func (a A) F() string {
	return a.Field
}

func source() string {
	return "a"
}

func sink(x string) {
	fmt.Println(x)
}

func runInterface(x Interface) {
	sink(x.F()) // this sink will be reached if x is tainted @Sink(A,C)
}

func main() {
	s := source() // this is a source @Source(A)
	x := A{Field: s}
	runInterface(x) // the sink here will be reached
	test()
}

// Example 2

type B struct {
	Field1 string
	Field2 string
}

func (b *B) Swap() {
	s := b.Field1
	b.Field1 = b.Field2
	b.Field2 = s
}

func (b *B) F() string {
	return b.Field2
}

func test() {
	x := B{
		Field1: source(), // this is a source @Source(C)
		Field2: "ok",
	}
	sink(x.Field2)   // No alarm is raised here!
	runInterface(&x) // the sink here will be reached
	test3()
}

// Example 3

type C struct {
	Field1 string
}

func (c *C) F() string {
	sink(c.Field1) // @Sink(B)
	return c.Field1
}

func runInterface2(x Interface) {
	fmt.Println(x.F())
}

func test3() {
	x := C{
		Field1: source(), // this is a source @Source(B)
	}
	runInterface2(&x) // the sink here will be reached
}
