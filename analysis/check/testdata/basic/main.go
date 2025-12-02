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

func twoArgInterBool(x, y int) bool {
	return gt(x, y, 0)
}

func gt(x, y, z int) bool {
	// NOTE x does not flow to the return value here because it's the condition of an if-statement,
	// but y does flow to the return value.
	//
	// This is a weird artifact of Go's SSA representation:
	// func gt(x int, y int, z int) bool:
	// 0:                                                                entry P:0 S:2
	// 	t0 = x > z                                                         bool
	// 	if t0 goto 2 else 1
	// 1:                                                            binop.rhs P:1 S:1
	// 	t1 = y > z                                                         bool
	// 	jump 2
	// 2:                                                           binop.done P:2 S:0
	// 	t2 = phi [0: true:bool, 1: t1] #||                                 bool
	// 	return t2

	return x > z || y > z
}

func testTwoArgInterBool() {
	fmt.Println(twoArgInterBool(1, 2)) // true
}

func twoArgInter(x, y int) int {
	return plus(x, y, 3)
}

func plus(x, y, z int) int {
	return x + y + z
}

func testTwoArgInter() {
	fmt.Println(twoArgInter(1, 2)) // 6
}

func threeArgInter(no *int, a *int, b *int) int {
	x := add2(*a, *a, no)
	x += add2(*a, *b, no)
	*b = x
	return x
}

func add2(a int, b int, no *int) int {
	return a + b
}

func testThreeArgInter() {
	x, y, z := 0, 1, 2
	res := threeArgInter(&x, &y, &z)
	fmt.Println(res) // 5
}

func main() {
	testSingleArgIntraOut()
	testSingleArgInterNone()
	testTwoArgIntraInout()
	testTwoArgInterInout()
	testSingleArgIntraGlobal()
	testSingleArgInterGlobal()
	testTwoArgInterBool()
	testTwoArgInter()
	testThreeArgInter()
}
