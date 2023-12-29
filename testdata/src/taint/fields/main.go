// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "fmt"

type example struct {
	ptr *string
}

type Node struct {
	label string
	next  *Node
}

type nestedStruct struct {
	Ex example
	A  string
	B  string
	C  string
}

type AStruct struct {
	A string
}
type StructEmbed struct {
	AStruct
	OtherData string
}

func source() string {
	return "!taint!"
}

func source2() *nestedStruct {
	return &nestedStruct{
		Ex: example{},
		A:  "tainted",
		B:  "initial-B",
	}
}

func mkTaintedStructField() AStruct {
	return AStruct{A: source()} // @Source(mkTaintedStructField)
}

func newStruct() *nestedStruct {
	return &nestedStruct{
		Ex: example{},
		A:  "initial-A",
		B:  "initial-B",
	}
}

func passing(s1 string, s2 string) string {
	return s1 + s2
}

func sink(s string) {
	fmt.Printf("Sink: %s\n", s)
}

func sink2(a any) {
	fmt.Printf("%t", a)
}

func testSimpleField1() {
	x := newStruct()
	x.A = source() // @Source(testSimpleField_1)
	x.B = "ok"
	sink(x.B)
	sink(x.A) // @Sink(testSimpleField_1)
	sink(x.C)
}

func testSimpleField2() {
	x := newStruct()
	s := &x.A
	x.A = source() // @Source(testSimpleField_2)
	x.B = "ok"
	x.C = source() // @Source(testSimpleField_3)
	b := make([]string, 10)
	b[0] = *s
	sink(x.B)
	sink(x.A)  // @Sink(testSimpleField_2)
	sink(x.C)  // @Sink(testSimpleField_3)
	sink(*s)   // @Sink(testSimpleField_2)
	sink(b[1]) // @Sink(testSimpleField_2)
}

func testAllStructTainted() {
	x := source2() // @Source(testAllStructTainted)
	x.B = "ok"
	sink(x.B) // @Sink(testAllStructTainted)
	sink(x.A) // @Sink(testAllStructTainted)
	sink2(x)  // @Sink(testAllStructTainted)
}

func testFieldEmbedded() {
	s1 := StructEmbed{AStruct: AStruct{A: "tainted"}, OtherData: "not tainted"}
	s1.AStruct.A = source() // @Source(testFieldEmbedded)
	s2 := "ok"
	s3 := passing(s1.A, s2)
	s4 := fmt.Sprintf("%s", s3)
	sink(s4) // @Sink(testFieldEmbedded)
	sink(s1.OtherData)
}

func testFieldEmbedded2() {
	s1 := StructEmbed{AStruct: AStruct{A: "tainted"}, OtherData: "not tainted"}
	s1.A = source() // @Source(testFieldEmbedded2)
	s2 := "ok"
	s3 := passing(s1.AStruct.A, s2)
	s4 := fmt.Sprintf("%s", s3)
	sink(s4) // @Sink(testFieldEmbedded2)
	sink(s1.OtherData)
	sink(s1.A) // @Sink(testFieldEmbedded2)
}

func testFromFunctionTaintingField() {
	x := mkTaintedStructField()
	sink(x.A) // @Sink(mkTaintedStructField)
}

func testFieldAndSlice() {
	fmt.Println("testFieldAndSlice")
	s := source() // @Source(testFieldAndSlice)
	s2 := s + "ok"
	a := make([]*Node, 10)
	x := &Node{label: s2}
	a[0] = &Node{label: "ok"}
	a[1] = &Node{label: "fine"}
	a[0].next = a[1]
	a[1].next = x // a[0] -> a[1] -> x (tainted)
	testFieldAndSliceSink(a)
}

func testFieldAndSliceSink(a []*Node) {
	for _, x := range a {
		if x != nil {
			sink(x.label) // @Sink(testFieldAndSlice)
			if x.next != nil {
				sink(x.next.label) // @Sink(testFieldAndSlice)
			}
		}
	}
}

func testInterProceduralFieldSensitivity() {
	x := newStruct()
	s := &x.A
	x.A = source() // @Source(testSimpleFieldInter_A)
	x.B = "ok"
	x.C = source() // @Source(testSimpleFieldInter_C)
	b := make([]string, 10)
	b[0] = *s
	testInterProceduralFieldSensitivityCallee(x)
}

func testInterProceduralFieldSensitivityCallee(x *nestedStruct) {
	sink(x.B)
	sink(x.A) // @Sink(testSimpleFieldInter_A)
	sink(x.C) // @Sink(testSimpleFieldInter_C)
}

func main() {
	testSimpleField1()
	testSimpleField2()
	testAllStructTainted()
	testFieldEmbedded()
	testFieldEmbedded2()
	testFromFunctionTaintingField()
	testFieldAndSlice()
	testInterProceduralFieldSensitivity()
}
