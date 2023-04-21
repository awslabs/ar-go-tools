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

type I interface {
	f()
	g(int) string
}

type J interface {
	h(string) int
}

// A implements I

type A struct {
	Data string
}

func (a A) f() {
	fmt.Println(a.Data)
}

func (a A) g(i int) string {
	return fmt.Sprintf("%s-%d", a.Data, i)
}

// B implements I, J, io.Writer

type B struct {
	Index int
}

func (b B) f() {
	fmt.Println(b.Index)
}

func (b B) g(i int) string {
	return fmt.Sprintf("%d%d", b.Index, i)
}

func (b B) Write(p []byte) (int, error) {
	return len(p), nil
}

func (b B) h(s string) int {
	return len(s) + b.Index
}

func callInterfaceIMethod(i I) {
	i.f()
	fmt.Println(i.g(0))
}

func callInterfaceJMethod(j J) {
	fmt.Println(j.h("0"))
}

func main() {
	a := A{Data: "example"}
	b := B{Index: 0}
	callInterfaceIMethod(a)
	callInterfaceJMethod(b)
	callInterfaceIMethod(b)
}
