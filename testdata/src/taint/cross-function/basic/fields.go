package main

import "fmt"

type Example struct {
	SourceField string
	OtherData   string
}

func testField() {
	s := Example{SourceField: "tainted", OtherData: "not tainted"} // @Source(field1)
	s2 := "ok"
	s3 := passing(s.SourceField, s2) // @Source(field2) is the closest to the sink
	s4 := fmt.Sprintf("%s", s3)
	sink1(s4) // tainted data reaches this @Sink(field1,field2)
}

type SourceStruct struct {
	Source1 string
}
type SourceEmbed struct {
	SourceStruct
	OtherData string
}

func testFieldEmbedded() {
	s1 := SourceEmbed{SourceStruct: SourceStruct{Source1: "tainted"}, OtherData: "not tainted"} // @Source(embedded1)
	s2 := "ok"
	s3 := passing(s1.Source1, s2) // @Source(embedded2)
	s4 := fmt.Sprintf("%s", s3)
	sink1(s4) // @Sink(embedded1,embedded2)
}
