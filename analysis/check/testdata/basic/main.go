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

func singleArgIntraOut(x int) int {
	return x
}

func singleArgInterNone(x int) int {
	return noop(x)
}

func noop(int) int {
	return 0
}

func twoArgIntraInout(x *int, y *int) {
	*y = *x
}

func twoArgInterInout(x *int, y *int) {
	setmem(y, *x)
}

func setmem(dst *int, src int) {
	*dst = src
}

var global int

func singleArgIntraGlobal(x int) int {
	global = x
	return global
}

func singleArgInterGlobal(x int) int {
	setmem(&global, x)
	return global
}

func testSingleArgIntraOut() {
	fmt.Println(singleArgIntraOut(1))
}

func testSingleArgInterNone() {
	fmt.Println(singleArgInterNone(1))
}

func testTwoArgIntraInout() {
	x := 1
	y := -1
	twoArgIntraInout(&x, &y)
	fmt.Println(y)
}

func testTwoArgInterInout() {
	x := 1
	y := -1
	twoArgInterInout(&x, &y)
	fmt.Println(y)
}

func testSingleArgIntraGlobal() {
	fmt.Println(singleArgIntraGlobal(1)) // 1
	fmt.Println(global)                  // 1
}

func testSingleArgInterGlobal() {
	fmt.Println(singleArgInterGlobal(2)) // 2
	fmt.Println(global)                  // 2
}

func main() {
	testSingleArgIntraOut()
	testSingleArgInterNone()
	testTwoArgIntraInout()
	testTwoArgInterInout()
	testSingleArgIntraGlobal()
	testSingleArgInterGlobal()
}
