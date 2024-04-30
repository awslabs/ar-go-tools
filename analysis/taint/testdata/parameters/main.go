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
	"os/exec"
)

type A struct {
	Field string
}

func main() {
	test1()
	testHowAgentExecutes()
	test2()
	test3()
	test4()
	test5()
}

// This set of examples tests taint tracking across function calls that appear as parameters of other functions
func test1() {
	a := A{Field: "ok"}
	f = h
	g(&a, f)
}

func source(x string) string {
	return x + "taint"
}

func sink(x any) {
	fmt.Println(x)
}

var f = func(a *A) string {
	return a.Field
}

func g(a *A, b func(a *A) string) {
	x := b(a)
	fmt.Println(x)
	sink(x) // @Sink(taintField)
}

func h(a *A) string {
	return fmt.Sprintf("f(%s)", source(a.Field)) // @Source(taintField)
}

// Test

func testHowAgentExecutes() {
	dir := source("basedir/") // @Source(dir)
	command := exec.Command("someexec", "somearg")
	command.Dir = dir
	_ = command.Start() // @Sink(dir)
}

// Test 2

func test2() {
	ok := "ok"
	taintOkWithoutReference(ok)
	sink(ok)
}

func taintOkWithoutReference(v string) {
	invisibleTaint(v)
}

func invisibleTaint(v string) {
	v = source("tainted")
}

// Test 3
func test3() {
	willTaint := "x"
	taintWithReference(&willTaint)
	sink(willTaint) // @Sink(test3)
}

func taintWithReference(v *string) {
	visibleTaint(v)
}

func visibleTaint(v *string) {
	*v = source("tainted") // @Source(test3)
}

// Test 4
func test4() {
	ok := "y"
	taintWithReference2(&ok)
	sink(ok)
}

func taintWithReference2(v *string) {
	invisibleTaint(*v)
}

func test5() {
	recursiveShifter(source("tainted"), "ok", "ok", "ok", "ok", "ok") // @Source(test5)
	// In the next call, source is erased before reaching the sink between recursive calls
	recursiveShifterResets(source("tainted"), "ok", "ok", "ok", "ok", "ok")
}

func recursiveShifter(a, b, c, d, e, f string) {
	if a == "ok" {
		sink(f) // @Sink(test5)
	}
	recursiveShifter(b, c, d, e, f, a)
}

func recursiveShifterResets(a, b, c, d, e, f string) {
	if a == "ok" {
		sink(f) // never reached
	}
	recursiveShifter(b, c, d, e, f, "ok")
}
