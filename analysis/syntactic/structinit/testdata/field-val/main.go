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

type target struct {
	x int
}

type nestedTarget struct {
	t target
	x int
}

type nestedTargetPtr struct {
	t *target
	x int
}

const One = 1

// NOTE print statements ensure the variables aren't erased in SSA form.
// They also test implicit interface conversions to the `any` type.

func testZeroAlloc() {
	var ex1 target
	fmt.Println(ex1) // @ZeroAlloc(target)

	ex2 := &target{} // @ZeroAlloc(target)
	fmt.Println(ex2)

	ex3 := &target{} // ok because of write
	ex3.x = 1
	fmt.Println(ex3)

	var ex4 nestedTarget
	fmt.Println(ex4) // @ZeroAlloc(target)

	var ex5 nestedTargetPtr
	fmt.Println(ex5) // @ZeroAlloc(target)

	ex6 := nestedTargetPtr{t: &target{}, x: 1} // @ZeroAlloc(target)
	fmt.Println(ex6)

	ex7 := nestedTargetPtr{}
	fmt.Println(ex7) // @ZeroAlloc(target)

	ex8 := nestedTarget{}
	fmt.Println(ex8) // @ZeroAlloc(target)

	ex9 := struct{ x int }(target{}) // @ZeroAlloc(target)
	fmt.Println(ex9)

	ex10 := target(struct{ x int }{}) // @ZeroAlloc(target)
	fmt.Println(ex10)
}

func testUntypedConstAlloc() {
	ex1 := target{x: 1} // ok
	fmt.Println(ex1)

	ex2 := target{x: -1} // @InvalidWrite(target)
	fmt.Println(ex2)

	ex3 := &target{x: -1} // @InvalidWrite(target)
	fmt.Println(ex3)

	ex4 := nestedTarget{t: target{x: 1}} // ok
	fmt.Println(ex4)

	ex5 := nestedTargetPtr{t: &target{x: 1}} // ok
	fmt.Println(ex5)

	ex6 := nestedTarget{t: target{x: -1}} // @InvalidWrite(target)
	fmt.Println(ex6)

	ex7 := nestedTargetPtr{t: &target{x: -1}} // @InvalidWrite(target)
	fmt.Println(ex7)

	ex8 := struct{ x int }(target{x: -1}) // @InvalidWrite(target) // @ZeroAlloc(target) // TODO zero-alloc false positive
	fmt.Println(ex8)

	ex9 := target(struct{ x int }{x: -1}) // @InvalidWrite(target) // @ZeroAlloc(target) // TODO zero-alloc false positive
	fmt.Println(ex9)
}

func testTypedConstAlloc() {
	ex1 := target{x: One} // ok
	fmt.Println(ex1)

	ex2 := target{x: -One} // @InvalidWrite(target)
	fmt.Println(ex2)

	ex3 := &target{x: -One} // @InvalidWrite(target)
	fmt.Println(ex3)

	ex4 := nestedTarget{t: target{x: One}} // ok
	fmt.Println(ex4)

	ex5 := nestedTargetPtr{t: &target{x: One}} // ok
	fmt.Println(ex5)

	ex6 := nestedTarget{t: target{x: -One}} // @InvalidWrite(target)
	fmt.Println(ex6)

	ex7 := nestedTargetPtr{t: &target{x: -One}} // @InvalidWrite(target)
	fmt.Println(ex7)

	ex8 := struct{ x int }(target{x: -One}) // @InvalidWrite(target) // @ZeroAlloc(target) // TODO zero-alloc false positive
	fmt.Println(ex8)

	ex9 := target(struct{ x int }{x: -One}) // @InvalidWrite(target)// @ZeroAlloc(target) // TODO zero-alloc false positive
	fmt.Println(ex9)
}

func main() {
	testZeroAlloc()
	testUntypedConstAlloc()
	testTypedConstAlloc()
}
