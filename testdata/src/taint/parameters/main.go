package main

import (
	"fmt"
	"os/exec"
)

type A struct {
	Field string
}

func main() {
	test1()
	testHowAgentExecutes()
}

// This set of examples tests taint tracking across function calls that appear as parameters of other functions
func test1() {
	a := A{Field: "ok"}
	f = h
	g(&a, f)
}

func source(x string) string {
	return x + "taint"
}

func sink(x any) {
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

// Test 2

func testHowAgentExecutes() {
	dir := source("basedir/") // @Source(dir)
	command := exec.Command("someexec", "somearg")
	command.Dir = dir
	_ = command.Start() // @Sink(dir)
}
