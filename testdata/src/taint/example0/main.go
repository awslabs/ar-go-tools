package main

import "fmt"

type example struct {
	ptr *string
}

type nestedStruct struct {
	Ex example
	A  string
}

func source() string {
	return "tainted data"
}

func source2() nestedStruct {
	return nestedStruct{
		Ex: example{},
		A:  "tainted",
	}
}

func sink(_ string) {

}

func generate() *nestedStruct {
	n := source2() // @Source(ex)
	return &n
}

func genFunc(n *nestedStruct) func() string {
	return func() string {
		return "(" + n.A + ")"
	}
}

func delta() {
	n := &nestedStruct{
		Ex: example{},
		A:  "ok",
	}
	f := genFunc(n)
	sink(f()) // @Sink(ex) TODO: reached because pointer analysis is not context sensitive
}

func test() {
	n := generate()
	f := genFunc(n)
	s := f()
	fmt.Printf(s)
}

func main() {
	test()
	delta()
}
