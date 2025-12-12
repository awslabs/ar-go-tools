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

func threeArgInterDiffCallees(no, a, b *int) int {
	x := add1(*a, *a, no)
	x += add2(*a, *b, no)
	*b = x
	return x
}

func add1(a int, b int, no *int) int {
	return a + 1
}

func testThreeArgInterDiffCallees() {
	x, y, z := 0, 1, 2
	res := threeArgInterDiffCallees(&x, &y, &z)
	fmt.Println(res) // 5
}

type container struct {
	field *data
	other *data
}

type data struct {
	value int
}

func propagateFields(src, dst *container) {
	dst.field = addVals(src.field, src.other)
	dst.other = addVals(src.other, src.field)
}

func addVals(a, b *data) *data {
	return &data{value: a.value + b.value}
}

func testFieldPropagation() {
	x := &container{field: &data{0}, other: &data{1}}
	y := &container{field: &data{2}, other: &data{2}}
	propagateFields(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
	// x.field:0 x.other:1, y.field:1 y.other:1
}

func aliasPtr(out **int, a, b *int) {
	setPtsB(out, a, b)
}

func setPtsB(out **int, a, b *int) {
	*out = b
}

func testMutatePtr() {
	outv, a, b := new(int), new(int), new(int)
	*a = 0
	*b = -5
	outv = a
	aliasPtr(&outv, a, b)
	fmt.Println(*outv) // -5
}

type state struct {
	acc   int
	count int
}

func sharedMutation(a, b *int, shared *state) int {
	modify(a, shared)
	modify(b, shared)
	return shared.acc
}

func modify(val *int, s *state) {
	s.acc += *val
}

func testSharedMutation() {
	a, b := 0, 1
	st := &state{2, 3}
	res := sharedMutation(&a, &b, st)
	fmt.Println(res) // 3
}

func addPtrs(x, y *int) *int {
	sum := *x + *y
	return &sum
}

func storePtr(x, y *int) int {
	z := addPtrs(x, y)
	x = z
	return *x
}

func testStorePtr() {
	a, b := 0, 1
	res := storePtr(&a, &b)
	fmt.Println("testStorePtr", res)
}

func aliasNoop(x, y *int) {
	x = y
}

func testAliasInterNone() {
	x, y := new(int), new(int)
	*x = 0
	*y = 2
	aliasNoop(y, x)
	*x++
	fmt.Println("testAliasInterNone", *y) // 2
	// Does not print 1 because aliasNoop aliases a local copy of y and x, not the actual arguments
}

func alias(x ***int, y **int) {
	*x = y
}

func testAliasInter() {
	x, y := new(int), new(int)
	*x = 0
	*y = 2
	yp := &y
	alias(&yp, &x)
	*x++
	fmt.Println("testAliasInter", **yp) // 1
}

func writeStructPtr(x, y *state) {
	*x = *y
	// x.acc = y.acc
	// x.count = y.count
}

func testWriteStructPtr() {
	x := &state{}
	y := &state{acc: 1, count: 1}
	writeStructPtr(x, y)
	fmt.Println("testWriteStructPtr", x.count) // 1
}

func writeToClosed(x, y int) int {
	f := func() int {
		y = x
		return x
	}
	return f() + f()
}

func testClosure() {
	res := writeToClosed(0, -5)
	fmt.Println("testClosure", res) // 0
}

func nestedClosures(x, y *int) *int {
	bv := *y
	outer := func(z *int) *int {
		inner := func() *int {
			return z
		}
		res := *inner() + bv
		return &res
	}
	return outer(x)
}

func testNestedClosures() {
	a, b := 1, 2
	res := nestedClosures(&a, &b)
	fmt.Println("testNestedClosures", *res) // 3
}

func closureShared(x, y *int) *int {
	f1 := func() *int {
		*x = *y
		return x
	}
	f2 := func() *int {
		return y
	}
	f1()
	return f2()
}

func testClosureShared() {
	a, b := 1, 2
	res := closureShared(&a, &b)
	fmt.Println("testClosureShared", *res) // 2
}

func noFlowClosure(x, y *int) *int {
	f := func() *int {
		z := 42
		return &z
	}
	f()
	return x
}

func testNoFlowClosure() {
	a, b := 1, 2
	res := noFlowClosure(&a, &b)
	fmt.Println("testNoFlowClosure", *res) // 1
}

func nestedClosuresInvalid(x, y *int) *int {
	outer := func() *int {
		inner := func() *int {
			*x = *x + *y // x is a non-local bound label which cannot be soundly checked
			return x
		}
		return inner()
	}
	return outer()
}

func testNestedClosuresInvalid() {
	a, b := 1, 2
	res := nestedClosuresInvalid(&a, &b)
	fmt.Println("testNestedClosuresInvalid", *res) // 3
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
	testThreeArgInterDiffCallees()
	testFieldPropagation()
	testSharedMutation()
	testStorePtr()
	testMutatePtr()
	testAliasInterNone()
	testAliasInter()
	testWriteStructPtr()
	testClosure()
	testNestedClosures()
	testClosureShared()
	testNoFlowClosure()
	testNestedClosuresInvalid()
}
