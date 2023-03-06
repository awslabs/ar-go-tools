package main

func TestCopy() {
	a := []T{source1()} // @Source(ex1)
	b := make([]T, 2)
	n := copy(b, a)
	sink(n)
	sink(b[0]) // @Sink(ex1)
}

func TestAppend() {
	a := []T{source1()} // @Source(ex2)
	b := append(a, T{})
	sink(b) // @Sink(ex2)
}

func TestAppend2() {
	a := []T{{}, {}}
	b := append(a, source1()) // @Source(ex3)
	sink(a)                   // @Sink(ex3)
	sink(b)                   // @Sink(ex3)
}

func main() {
	TestCopy()
	TestAppend()
	TestAppend2()
}
