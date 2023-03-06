package main

import (
	"encoding/json"
	"sync"
)

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

func TestSyncDoOnce() {
	o := &sync.Once{}
	x := source1() // @Source(TestSyncDoOnce)
	o.Do(func() {
		sink2(x) // @Sink(TestSyncDoOnce)
	})
}

func main() {
	TestJsonUnmarshal()
	TestJsonMarshal()
	TestSyncDoOnce()
}
