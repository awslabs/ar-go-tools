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

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"strconv"
)

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
	fmt.Println("testSimpleField2")
	x := newStruct()
	s := &(x.A)
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
	fmt.Println("testAllStructTainted")
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

func testFieldAndMap() {
	fmt.Println("testFieldAndMap")
	s := source() // @Source(testFieldAndMap)
	s2 := s + "ok"
	a := make(map[string]*Node, 10)
	x := &Node{label: s2}
	a["0"] = &Node{label: "ok"}
	a["1"] = &Node{label: "fine"}
	a["0"].next = a["1"]
	a["1"].next = x // a[0] -> a[1] -> x (tainted)
	testFieldAndMapSink(a)
}

func testFieldAndMapSink(a map[string]*Node) {
	for _, x := range a {
		if x != nil {
			sink(x.label) // @Sink(testFieldAndMap)
		}
	}
}

func testFieldAndMapRev() {
	fmt.Println("testFieldAndMapRev")
	a := make(map[string]*Node, 10)
	x := &Node{label: "ok"}
	a["1"] = &Node{label: "fine"}
	a["0"] = &Node{label: "fine"}
	a["0"].next = a["1"]
	a["1"].next = x // a[0] -> a[1] -> x (tainted)
	testFieldAndMapSource(a)
	sink("rev-" + a["0"].label) // @Sink(testFieldAndMapSource)
}

func testFieldAndMapSource(a map[string]*Node) {
	for _, x := range a {
		if x != nil {
			x.label = source() // @Source(testFieldAndMapSource)
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

func testInterProceduralFieldSensitivityTwoDeep() {
	x := newStruct()
	b := source() // @Source(testSimpleFieldInter_ExPtr)
	x.Ex.ptr = &b
	x.B = "ok"
	testInterProceduralFieldSensitivityCalleeTwoDeep(x)
}

func testInterProceduralFieldSensitivityCalleeTwoDeep(x *nestedStruct) {
	sink(x.B)
	sink(x.A)
	sink(*x.Ex.ptr) // @Sink(testSimpleFieldInter_ExPtr)
}

func testInterProceduralFieldSensitivityMultiCall() {
	x := newStruct()
	b := source() // @Source(testSimpleFieldInter_Multi)
	x.Ex.ptr = &b
	x.B = "ok"
	testInterProceduralFieldSensitivityMultiOne(x)
}

func testInterProceduralFieldSensitivityMultiOne(x *nestedStruct) {
	sink(x.B)
	sink(x.A)
	testInterProceduralFieldSensitivityMultiTwo(x.Ex)
}

func testInterProceduralFieldSensitivityMultiTwo(x example) {
	sink(*x.ptr) // @Sink(testSimpleFieldInter_Multi)
}

func testDeepNodeSound() {
	z := &Node{label: source()} // @Source(deepNode)
	y := &Node{label: "ok", next: z}
	x := &Node{label: "ok", next: y}
	a := &Node{label: "ok", next: x}
	b := &Node{label: "ok", next: a}
	deepNodeCall(b)
}

func deepNodeCall(x *Node) {
	sink(x.next.label)
	// b.a.x.y.z
	sink(x.next.next.next.next.label) // @Sink(deepNode)
}

type MyInterface interface {
	SetLabel(string)
	GetAllData() string
}

type MyStruct struct {
	MyData string
	MySub  *Node
}

func NewMyStruct() MyStruct {
	return MyStruct{
		MyData: "default-data",
		MySub: &Node{
			label: "default-label",
			next:  nil,
		},
	}
}

func (m MyStruct) SetLabel(s string) {
	m.MySub.label = s
}

func (m MyStruct) GetAllData() string {
	return m.MyData + "_" + m.MySub.label
}

func testMethodTaintReceiver() {
	fmt.Println("testMethodTaintReceiver")
	x := NewMyStruct()
	x.SetLabel(source()) // @Source(methodTaintReceiver)
	s := x.GetAllData()
	sink(s) // @Sink(methodTaintReceiver)
}

type MyStructBis struct {
	MyDataBis string
	MySubBis  *Node
}

func NewMyStructBis() MyStructBis {
	return MyStructBis{
		MyDataBis: "default-data",
		MySubBis: &Node{
			label: "default-label",
			next:  nil,
		},
	}
}

func (m *MyStructBis) SetLabel(s string) {
	m.MySubBis.label = s
}

func (m *MyStructBis) GetAllData() string {
	return m.MyDataBis + "_" + m.MySubBis.label
}

func testMethodTaintReceiverPointer() {
	fmt.Println("testMethodTaintReceiverPointer")
	x := NewMyStructBis()
	x.SetLabel(source()) // @Source(methodTaintReceiverPointer)
	s := x.GetAllData()
	sink(s) // @Sink(methodTaintReceiverPointer)
}

func testMethodInterface() {
	fmt.Println("testMethodInterface")
	x := NewMyStruct()
	testMethodInterfaceTaintThroughInvoke(x) // this taints x.SubE.label
	sink(x.GetAllData())                     // @Sink(testMethodInterface)
}

func testMethodInterfaceTaintThroughInvoke(x MyInterface) {
	x.SetLabel(source()) //@Source(testMethodInterface)
}

func testRecursion() {
	x := NewMyStruct()
	x.MySub.next = &Node{
		label: "",
		next:  nil,
	}
	taintWithRecursion(x.MySub, 3)
	sink(x.MySub.next.label) //@Sink(inRecursion)
}

func taintWithRecursion(x *Node, n int) {
	if n <= 0 || x == nil {
		return
	}
	if n >= 3 {
		x.label = source() //@Source(inRecursion)
	}
	if x.next != nil {
		taintWithRecursion(x.next, n-1)
	}
}

func (m *MyStructBis) Move() {
	m.MySubBis.label = m.MyDataBis
}

func testMoveTaintBetweenFields() {
	x := NewMyStructBis()
	x.MyDataBis = source() // @Source(testMoveTaintBetweenFields)
	x.Move()
	sink(x.MySubBis.label) // @Sink(testMoveTaintBetweenFields)
}

type ValueStructInner struct {
	id int
}

type ValueStruct struct {
	inner   ValueStructInner
	content string
}

func testTaintStructAsValue() {
	v := ValueStructInner{id: len(source())} // @Source(testTaintStructAsValue)
	x := ValueStruct{inner: v, content: "ok"}
	callsSink(x)
}

func callsSink(x ValueStruct) {
	sink(x.content)
	sink(strconv.Itoa(x.inner.id)) // @Sink(testTaintStructAsValue)
}

type t struct {
	f func() string
	g func() string
}

func testStructWithFuncs() {
	data := source() // @Source(testStructWithFuncs)
	val := t{
		f: func() string {
			return data
		},
		g: func() string {
			return "safe"
		},
	}

	sink(val.f()) // @Sink(testStructWithFuncs)
	sink(val.g()) // safe
}

type Payload struct {
	MessageType string
	Version     int
	MessageId   string
	Payload     []byte
}

type Content struct {
	SchemaVersion int
	JobId         string
	Content       string
}

// GenerateAgentJobReplyPayload generates AgentJobReply agent message
func generatePayload(log *log.Logger, agentMessageUUID string, messageID string, replyPayload string) (*Payload, error) {
	payloadB, err := json.Marshal(replyPayload)
	if err != nil {
		return nil, err
	}
	payload := string(payloadB)
	log.Printf("Sending reply ")
	if len(payloadB) > 2000 {
		return nil, fmt.Errorf(
			"dropping reply message %v because it is too large to send over control channel", agentMessageUUID)
	}
	finalReplyContent := Content{
		SchemaVersion: 1,
		JobId:         messageID,
		Content:       payload,
	}

	finalReplyContentBytes, err := json.Marshal(finalReplyContent)
	if err != nil {
		log.Fatalf("Cannot build reply message %v", err)
		return nil, err
	}

	repMsg := &Payload{
		MessageType: "type-foo",
		Version:     1,
		MessageId:   agentMessageUUID,
		Payload:     finalReplyContentBytes,
	}
	return repMsg, nil
}

func testGeneratingPayloadWithTaintedData() {
	taintedId := source() // @Source(testGenPayload)
	payload, err := generatePayload(log.Default(), taintedId, "m-12341", "hello")
	if err != nil {
		panic("error")
	}
	sink(fmt.Sprintf("%s-%s", payload.MessageId, strconv.Itoa(rand.Int()))) // @Sink(testGenPayload)
}

func testGeneratingPayloadWithTaintedDataThroughEncoding() {
	taintedId := source() // @Source(testGenPayloadThroughEnc)
	payload, err := generatePayload(log.Default(), "m-1423", taintedId, "hello")
	if err != nil {
		panic("error")
	}
	sink(fmt.Sprintf("%s", string(payload.Payload))) //@Sink(testGenPayloadThroughEnc)
}

func main() {
	testSimpleField1()
	testSimpleField2()
	testAllStructTainted()
	testFieldEmbedded()
	testFieldEmbedded2()
	testFromFunctionTaintingField()
	testFieldAndSlice()
	testFieldAndMap()
	testFieldAndMapRev()
	testInterProceduralFieldSensitivity()
	testInterProceduralFieldSensitivityTwoDeep()
	testInterProceduralFieldSensitivityMultiCall()
	testDeepNodeSound()
	testMethodTaintReceiver()
	testMethodTaintReceiverPointer()
	testMethodInterface()
	testRecursion()
	testMoveTaintBetweenFields()
	testTaintStructAsValue()
	testStructWithFuncs()
	testGeneratingPayloadWithTaintedData()
	testGeneratingPayloadWithTaintedDataThroughEncoding()
}
