package main

import "fmt"

func test0() {
	s := source1() // @Source(A)
	s1 := copyInput(s, 1)
	s3 := ""
	copyInto(s1, &s3)
	argReachesSink(s3)
}

func copyInput(s string, x int) string {
	if x > 1 {
		return s
	} else {
		return s
	}
}

func copyInto(s string, s2 *string) {
	*s2 = s
}

func sink1(s string) {
	fmt.Println(s)
}

func argReachesSink(x string) {
	a := make([]string, 10)
	a[0] = "x"
	a[1] = "ok"
	a[2] = x
	sink1(a[2]) // want "reached by tainting call on line 6" @Sink(A)
}

func source1() string {
	return "tainted"
}

func main() {
	test0()
	test1()                // see bar.go
	test2()                // see example.go
	test3(10)              // see example.go
	test4()                // see example2.go
	test5()                // see example3.go
	testField()            // see fields.go
	testFieldEmbedded()    // see fields.go
	runSanitizerExamples() // see sanitizers.go
}
