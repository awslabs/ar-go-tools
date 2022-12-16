package main

import "fmt"

type A struct {
	Field string
}

// This set of examples tests taint tracking across function calls that appear as parameters of other functions
func main() {
	a := A{Field: "ok"}
	f = h
	g(&a, f)
}

func source(x string) string {
	return x + "taint"
}

func sink(x string) {
	fmt.Println(x)
}

var f = func(a *A) string {
	return a.Field
}

func g(a *A, b func(a *A) string) {
	x := b(a)
	fmt.Println(x)
	sink(x) // @Sink(taintField)
}

func h(a *A) string {
	return fmt.Sprintf("f(%s)", source(a.Field)) // @Source(taintField)
}
