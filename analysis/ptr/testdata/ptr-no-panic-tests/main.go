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

import "unsafe"

// Basic types

type MyInt int
type MyString string
type MyBool bool

// Array types

type IntArray [5]int
type StringArray [3]string

// Slice types

type IntSlice []int
type StringSlice []string

// Map types

type StringIntMap map[string]int
type IntStringMap map[int]string

// Channel types

type IntChan chan int
type SendOnlyChan chan<- string
type RecvOnlyChan <-chan bool

// Pointer types

type IntPtr *int
type StringPtr *string

// Function types

type SimpleFunc func()
type FuncWithArgs func(int, string) bool
type FuncWithVariadic func(string, ...int) error

// Struct types

type SimpleStruct struct {
	Field1 int
	Field2 string
}

type EmbeddedStruct struct {
	SimpleStruct
	Field3 bool
}

type StructWithTags struct {
	Field1 int    `json:"field1"`
	Field2 string `json:"field2,omitempty"`
}

// Interface types

type SimpleInterface interface {
	Method1()
}

type ComplexInterface interface {
	Method1() int
	Method2(string) error
	Method3(int, ...string) (bool, error)
}

type EmbeddedInterface interface {
	SimpleInterface
	Method4() string
}

// Type aliases

type MyIntAlias = int
type MyStructAlias = SimpleStruct

// Unsafe pointer

type UnsafePtr unsafe.Pointer

// Generic types (Go 1.18+)

type GenericStruct[T any] struct {
	Value T
}

type GenericInterface[T comparable] interface {
	Compare(T) bool
}

type GenericMap[K comparable, V any] map[K]V

// SimpleInterface implementations

type SimpleImpl1 struct{}

func (s SimpleImpl1) Method1() {}

type SimpleImpl2 struct {
	data int
}

func (s SimpleImpl2) Method1() {}

// ComplexInterface implementations

type ComplexImpl1 struct {
	value int
}

func (c ComplexImpl1) Method1() int {
	return c.value
}

func (c ComplexImpl1) Method2(string) error {
	return nil
}

func (c ComplexImpl1) Method3(int, ...string) (bool, error) {
	return true, nil
}

type ComplexImpl2 struct {
	name string
}

func (c ComplexImpl2) Method1() int {
	return len(c.name)
}

func (c ComplexImpl2) Method2(string) error {
	return nil
}

func (c ComplexImpl2) Method3(int, ...string) (bool, error) {
	return false, nil
}

// EmbeddedInterface implementations

type EmbeddedImpl1 struct {
	id int
}

func (e EmbeddedImpl1) Method1() {}

func (e EmbeddedImpl1) Method4() string {
	return "embedded1"
}

type EmbeddedImpl2 struct {
	tag string
}

func (e EmbeddedImpl2) Method1() {}

func (e EmbeddedImpl2) Method4() string {
	return e.tag
}

// GenericInterface implementations

type GenericImpl1[T comparable] struct {
	value T
}

func (g GenericImpl1[T]) Compare(other T) bool {
	return g.value == other
}

type GenericImpl2[T comparable] struct {
	items []T
}

func (g GenericImpl2[T]) Compare(other T) bool {
	for _, item := range g.items {
		if item == other {
			return true
		}
	}
	return false
}

func fooChans() {
	// Use channel types
	var intCh IntChan = make(chan int, 1)
	var sendCh SendOnlyChan = make(chan string, 1)
	var recvCh RecvOnlyChan = make(chan bool, 1)

	intCh <- 42
	<-intCh

	sendCh <- "hello"

	select {
	case <-recvCh:
	default:
	}
}

func fooMaps() {
	// Use map types
	var stringIntMap StringIntMap = make(map[string]int)
	var intStringMap IntStringMap = make(map[int]string)
	var genericMap GenericMap[string, int] = make(map[string]int)

	stringIntMap["key"] = 42
	intStringMap[1] = "value"
	genericMap["generic"] = 100

	_ = stringIntMap["key"]
	_ = intStringMap[1]
	_ = genericMap["generic"]
}

func fooUnsafe() {
	// Use pointer types
	s := "hello"
	var strPtr StringPtr = &s

	arr := StringArray{"a", "b", "c"}

	// Unsafe pointer operations
	var unsafePtr = UnsafePtr(strPtr)
	var backToStrPtr StringPtr = (*string)(unsafePtr)

	// Array to slice conversion with unsafe
	arrPtr := unsafe.Pointer(&arr[0])
	slicePtr := (*string)(arrPtr)

	// Pointer arithmetic (unsafe)
	nextPtr := unsafe.Pointer(uintptr(arrPtr) + unsafe.Sizeof(arr[0]))
	nextStr := (*string)(nextPtr)

	// Use the values
	_ = *strPtr
	_ = *backToStrPtr
	_ = *slicePtr
	_ = *nextStr
	_ = unsafe.Sizeof(arr)
	_ = uintptr(unsafePtr)
}

func fooStructs() {
	// Use struct types
	var simple = SimpleStruct{Field1: 10, Field2: "simple"}
	var embedded = EmbeddedStruct{
		SimpleStruct: SimpleStruct{Field1: 20, Field2: "embedded"},
		Field3:       true,
	}
	var tagged = StructWithTags{Field1: 30, Field2: "tagged"}
	var generic = GenericStruct[int]{Value: 40}

	// Use type aliases
	var aliasStruct = MyStructAlias{Field1: 50, Field2: "alias"}
	var aliasInt MyIntAlias
	aliasInt = simple.Field1

	// Access fields
	_ = simple.Field2
	_ = embedded.Field1
	_ = embedded.Field2
	_ = embedded.Field3
	_ = tagged.Field1
	_ = tagged.Field2
	_ = generic.Value
	_ = aliasStruct.Field1
	_ = aliasStruct.Field2
	_ = aliasInt
}

func fooFuncs() {
	// Use function types
	var simple SimpleFunc = func() {}
	var withArgs FuncWithArgs = func(i int, s string) bool { return i > 0 }
	var variadic FuncWithVariadic = func(s string, nums ...int) error { return nil }

	simple()
	result := withArgs(42, "test")
	err := variadic("hello", 1, 2, 3)

	_ = result
	_ = err
}

func fooSlices() {
	// Use slice types
	var intSlice IntSlice = []int{1, 2, 3}
	var stringSlice StringSlice = []string{"a", "b", "c"}

	intSlice = append(intSlice, 4)
	stringSlice = append(stringSlice, "d")

	for _, v := range intSlice {
		_ = v
	}

	for _, v := range stringSlice {
		_ = v
	}
}

func foo() {
	// Use SimpleInterface implementations
	var simple1 SimpleInterface = SimpleImpl1{}
	var simple2 SimpleInterface = SimpleImpl2{data: 10}
	simple1.Method1()
	simple2.Method1()

	// Use ComplexInterface implementations
	var complex1 ComplexInterface = ComplexImpl1{value: 5}
	var complex2 ComplexInterface = ComplexImpl2{name: "test"}
	complex1.Method1()
	err := complex1.Method2("hello")
	if err != nil {
		return
	}
	_, err = complex1.Method3(1, "a", "b")
	if err != nil {
		return
	}
	complex2.Method1()
	err2 := complex2.Method2("world")
	if err2 != nil {
		return
	}
	_, err4 := complex2.Method3(2, "c", "d")
	if err4 != nil {
		return
	}

	// Use EmbeddedInterface implementations
	var embedded1 EmbeddedInterface = EmbeddedImpl1{id: 1}
	var embedded2 EmbeddedInterface = EmbeddedImpl2{tag: "tag1"}
	embedded1.Method1()
	embedded1.Method4()
	embedded2.Method1()
	embedded2.Method4()

	// Use GenericInterface implementations
	var generic1 GenericInterface[int] = GenericImpl1[int]{value: 42}
	var generic2 GenericInterface[string] = GenericImpl2[string]{items: []string{"a", "b"}}
	generic1.Compare(42)
	generic2.Compare("a")
}

func main() {
	foo()
	fooFuncs()
	fooChans()
	fooMaps()
	fooSlices()
	fooStructs()
	fooUnsafe()

	// Use the types to ensure they're analyzed
	var i MyInt = 42
	var s MyString = "hello"
	var b MyBool = true

	var arr IntArray = [5]int{1, 2, 3, 4, 5}
	var slice IntSlice = []int{1, 2, 3}
	var m StringIntMap = make(map[string]int)
	var ch IntChan = make(chan int)

	var j = 100
	var ptr IntPtr = &j
	var fn SimpleFunc = func() {}

	var st = SimpleStruct{Field1: 1, Field2: "test"}
	var embedded = EmbeddedStruct{
		SimpleStruct: st,
		Field3:       true,
	}

	var generic = GenericStruct[int]{Value: 42}
	var genericMap GenericMap[string, int] = make(map[string]int)

	// Use variables to prevent optimization
	_ = i
	_ = s
	_ = b
	_ = arr
	_ = slice
	_ = m
	_ = ch
	_ = ptr
	_ = fn
	_ = st
	_ = embedded
	_ = generic
	_ = genericMap
}
