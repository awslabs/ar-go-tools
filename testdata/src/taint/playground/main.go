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
	"fmt"
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

func source() string {
	return "!taint!"
}

func newStruct() *nestedStruct {
	return &nestedStruct{
		Ex: example{},
		A:  "initial-A",
		B:  "initial-B",
	}
}

func sink(s string) {
	fmt.Printf("Sink: %s\n", s)
}

type S struct {
	next *S
	v    string
}

func testSimpleField1() {
	x := newStruct()
	x.A = source() // @Source(testSimpleField_1)
	x.B = "ok"
	sink(x.B)
	sink(x.A) // @Sink(testSimpleField_1)
	sink(x.C)
}

func main() {
	testSimpleField1()
}
