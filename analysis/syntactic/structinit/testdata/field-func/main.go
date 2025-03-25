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
)

type target struct {
	f    func() int
	Flag int
}

type nested struct {
	target
}

type nestedPtr struct {
	*target
}

func Func() int {
	return 1
}

func invalid() int {
	return 1
}

func allowedBadInit() target {
	ex1 := target{f: nil} // ok: this is filtered out
	return ex1
}

func testWrites() {
	ex1 := target{f: nil} // @InvalidWrite(target)
	fmt.Println(ex1)

	ex2 := &target{f: nil} // @InvalidWrite(target)
	fmt.Println(ex2)

	ex3 := target{f: Func} // ok
	fmt.Println(ex3)

	f := Func
	ex4 := target{f: f} // ok
	fmt.Println(ex4)

	ex5 := target{f: invalid} // @InvalidWrite(target)
	fmt.Println(ex5)

	g := invalid
	ex6 := target{g, 1} // @InvalidWrite(target)
	fmt.Println(ex6)

	ex7 := target{func() int { return Func() }, 1} // @InvalidWrite(target)
	fmt.Println(ex7)
}

func testNestedWrites() {
	ex1 := nested{target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex1)

	ex2 := &nested{target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex2)

	ex3 := nestedPtr{&target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex3)

	ex4 := &nestedPtr{&target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex4)

	ex5 := nested{target{f: Func}} // ok
	fmt.Println(ex5)

	ex6 := &nested{target{f: Func}} // ok
	fmt.Println(ex6)

	ex7 := nestedPtr{&target{f: Func}} // ok
	fmt.Println(ex7)

	ex8 := &nestedPtr{&target{f: Func}} // ok
	fmt.Println(ex8)
}

func testMustReinit() {
	// Reinitialized
	reinitializeMe := allowedBadInit()
	reinitializeMe.f = Func // ok
	fmt.Println(reinitializeMe)
	// Not reinitialized
	fmt.Print("Some stuff!")
	badInit := allowedBadInit() // @BadReinit(target)
	fmt.Println(badInit)
	if rand.Int() > 0 {
		// Not reinitialized 2
		fmt.Print("Some stuff!")
		badInit2 := allowedBadInit() // @BadReinit(target)
		badInit2.Flag = 42
		fmt.Println(badInit2)
	}
	if rand.Int() > 0 {
		fmt.Print("Some stuff!")
		okInit := allowedBadInit()
		okInit.f = Func // ok : in same block
		fmt.Println(okInit)
	}
}

func testMustReinit2() {
	// Reinitialized
	reinitializeMe := allowedBadInit() // @BadReinit(target)
	if rand.Float32() > 1.0 {
		reinitializeMe.f = Func // reinitialized in a different block
		fmt.Println(reinitializeMe)
	}
}

func testMustReinit3() {
	// Reinitialized
	reinitializeMe := allowedBadInit() // @BadReinit(target)
	reinitializeMe.Flag = 0
	reinitializeMe.f = Func // field that must be reinitialized initialized after another field
	fmt.Println(reinitializeMe)
}

func main() {
	testWrites()
	testNestedWrites()
	testMustReinit()
	testMustReinit2()
	testMustReinit3()
}
