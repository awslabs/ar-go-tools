package main

import "encoding/json"

func TestJsonUnmarshal() {
	x := source1() // @Source(TestJsonUnmarshal)
	s := "{\"Data\": \"x\", \"Other\":" + x.Other + "}"
	y := T{}
	json.Unmarshal([]byte(s), &y)
	sink1(y.Data) // @Sink(TestJsonUnmarshal)
}

func TestJsonMarshal() {
	x := source1() // @Source(TestJsonMarshal)
	s, err := json.Marshal(x)
	if err != nil {
		return
	}
	sink1(string(s)) // @Sink(TestJsonMarshal)
}

func main() {
	TestJsonUnmarshal()
	TestJsonMarshal()
}
