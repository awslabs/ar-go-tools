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
	"math/rand"
	"reflect"
	"strconv"
	"unsafe"
)

func mayPanic() {
	panic("a problem")
}

func Source() string {
	return "x" + strconv.Itoa(rand.Int())
}

func Sink(x string) {
	fmt.Println(x)
}

type Example struct {
	x int
	f string
}

func (e Example) String() string {
	return e.f + strconv.Itoa(e.x)
}

func usingUnsafe() {
	s := Example{
		x: 1243,
		f: Source(),
	}
	x := []string{"a", "b", "c"}
	var i uintptr
	i = 3
	// equivalent to f := unsafe.Pointer(&s.f)
	f := unsafe.Pointer(uintptr(unsafe.Pointer(&s)) + unsafe.Offsetof(s.f))
	// equivalent to e := unsafe.Pointer(&x[i])
	e := unsafe.Pointer(uintptr(unsafe.Pointer(&x[0])) + i*unsafe.Sizeof(x[0]))

	fmt.Println(e, f)
}

func usingReflect() {
	x := 10
	name := "Go Lang"
	example := Example{1, Source()} // @Source(reflect)
	fmt.Println(reflect.TypeOf(x))
	fmt.Println(reflect.TypeOf(name))
	fmt.Println(reflect.TypeOf(example))

	method := reflect.ValueOf(example).MethodByName("String")
	if !method.IsValid() {
		fmt.Println("ERROR: String is not implemented")
		return
	}
	e := method.Call(nil) // this call is elided by the pointer analysis and results in false negatives!
	Sink(e[0].String())   // @Sink(reflect)
}

func usingRecover() {
	defer func() {
		if r := recover(); r != nil {

			fmt.Println("Recovered. Error:\n", r)
		}
	}()
	mayPanic()
	fmt.Println("After mayPanic()")

}

func main() {
	usingUnsafe()
	usingReflect()
	usingRecover()
}
