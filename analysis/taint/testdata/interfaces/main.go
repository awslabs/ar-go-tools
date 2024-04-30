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

	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/interfaces/sub"
)

func main() {
	s := source() // this is a source @Source(A)
	x := A{Field: s}
	runInterface(x) // the sink here will be reached
	test()
	test4()
	testInterfacesAndEmbedding()
	testImportedPrivateEmbeddingPublic()
}

type Interface interface {
	F() string
}

type A struct {
	Field string
}

func (a A) F() string {
	return a.Field
}

func source() string {
	return "a"
}

func sink(x string) {
	fmt.Println(x)
}

func runInterface(x Interface) {
	sink(x.F()) // this sink will be reached if x is tainted @Sink(A)
	// Source C does not reach this, because F returns Field2 which is not tainted.
}

// Example 2

type B struct {
	Field1 string
	Field2 string
}

func (b *B) Swap() {
	s := b.Field1
	b.Field1 = b.Field2
	b.Field2 = s
}

func (b *B) F() string {
	return b.Field2
}

func test() {
	x := B{
		Field1: source(), // this is a source @Source(C)
		Field2: "ok",
	}
	sink(x.Field2)
	runInterface(&x) // the sink here will be reached
	test3()
}

// Example 3

type C struct {
	Field1 string
}

func (c *C) F() string {
	sink(c.Field1) // @Sink(B)
	return c.Field1
}

func runInterface2(x Interface) {
	fmt.Println(x.F())
}

func test3() {
	x := C{
		Field1: source(), // this is a source @Source(B)
	}
	runInterface2(&x) // the sink here will be reached
}

// Example 4

type D struct {
	Field string
}

func (d D) F() string {
	sink(d.Field) // @Sink(E)
	return d.Field
}

func test4() {
	x := D{
		Field: source(), // this is a source @Source(E)
	}
	var _ Interface = (*D)(nil) // D satisfies Interface
	f := D.F
	f(x) // the sink here will be reached
}

// test 5 : interfaces and embedding

type SubE struct {
	field string
}

func (s *SubE) F() string {
	sink(s.field) // @Sink(testInterfacesAndEmbedding)
	return s.field
}

type E struct {
	SubE
	foo bool
}

func NewE(field string, foo bool) E {
	return E{
		SubE: SubE{field: field},
		foo:  foo,
	}
}

type E2 struct {
	SubE
	bar bool
}

func NewE2(field string, foo bool) E2 {
	return E2{
		SubE: SubE{field: field},
		bar:  foo,
	}
}

func testInterfacesAndEmbedding() {
	e := NewE(source(), false) // @Source(testInterfacesAndEmbedding)
	e2 := NewE2("ok", true)
	fmt.Println(e.F() + e2.F())
}

// testImportedPrivateEmbeddingPublic: interfaces, embedding and non-package exported types

type HasCommonFunc interface {
	CommonFunc() string
}

func runCommonFunc(h HasCommonFunc) string {
	return h.CommonFunc()
}

func testImportedPrivateEmbeddingPublic() {
	t1 := sub.NewPrivateType1(source()) // @Source(test6)
	t2 := sub.NewPrivateType2("ok")
	sink(runCommonFunc(t1)) // @Sink(test6)
	sink(runCommonFunc(t2))
}
