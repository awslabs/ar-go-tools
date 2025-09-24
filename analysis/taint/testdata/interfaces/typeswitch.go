package main

import "fmt"

type Stringer interface {
	String() string
}

type TaintedString struct {
	value string
}

func (t TaintedString) String() string {
	return t.value
}

type CleanInt struct {
	value int
}

func (c CleanInt) String() string {
	return fmt.Sprintf("%d", c.value)
}

func processWithTypeSwitch(x interface{}) {
	// Both tainted sources flow to each sink because we lose the underlying imeplementation
	// when converting to an interface.
	switch v := x.(type) {
	case Stringer:
		sink(v.String()) // @Sink(typeswitch,typeswitch2)
	case string:
		sink(v) // @Sink(typeswitch2,typeswitch)
	default:
		sink("unknown")
	}
}

func testTypeSwitch() {
	tainted := TaintedString{value: source()} // @Source(typeswitch)
	clean := CleanInt{value: 42}
	taintedStr := source() // @Source(typeswitch2)

	processWithTypeSwitch(tainted)    // should reach sink
	processWithTypeSwitch(clean)      // should not reach sink
	processWithTypeSwitch(taintedStr) // should reach sink
}
