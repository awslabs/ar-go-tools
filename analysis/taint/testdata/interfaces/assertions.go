package main

type DataHolder interface {
	GetData() string
}

type TaintedHolder struct {
	data string
}

func (t TaintedHolder) GetData() string {
	return t.data
}

type CleanHolder struct {
	data string
}

func (c CleanHolder) GetData() string {
	return c.data
}

func processWithAssertion(x interface{}) {
	if holder, ok := x.(DataHolder); ok {
		sink(holder.GetData()) // @Sink(assertion1)
	}
}

func processWithAssertion2(x interface{}) {
	if holder, ok := x.(DataHolder); ok {
		sink(holder.GetData())
	}
}

func processWithDirectAssertion(x interface{}) {
	holder := x.(DataHolder) // panic if not DataHolder
	sink(holder.GetData())   // @Sink(assertion2)
}

func processStringAssertion(x interface{}) {
	if s, ok := x.(string); ok {
		sink(s) // @Sink(assertion3)
	}
}

func testAssertions() {
	tainted := TaintedHolder{data: source()} // @Source(assertion1)
	clean := CleanHolder{data: "clean"}
	taintedStr := source() // @Source(assertion3)

	processWithAssertion(tainted) // should reach sink
	processWithAssertion2(clean)  // should not reach sink

	processWithDirectAssertion(TaintedHolder{data: source()}) // @Source(assertion2)

	processStringAssertion(taintedStr) // should reach sink inside that function
}
