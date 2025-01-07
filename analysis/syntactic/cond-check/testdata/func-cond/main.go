// Copyright (c)
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
//   Licensed under the Apache License, Version 2.0 (the "License").
//   You may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package main

import (
	"fmt"
	"math/rand"
)

type G struct {
	x int
}

func FooFunc(g G) {
	fmt.Println("FooFunc")
}

func FooPreCheck() bool {
	return rand.Int() > 10
}

func ResourceCheck() (bool, error) {
	if rand.Int() > 12 {
		return false, fmt.Errorf("err")
	}
	return true, nil
}

func callFooChecked() {
	b := FooPreCheck()
	if !b {
		return
	}
	FooFunc(G{})
}

func callFooWrongChecked() {
	b := FooPreCheck()
	if b {
		return
	}
	FooFunc(G{}) // @InvalidCall(funcCond)
}

func callFooCheckedPathNoReturns() {
	b := FooPreCheck()
	if !b {
		fmt.Println("Should return!")
	}
	FooFunc(G{}) // @InvalidCall(funcCond)
}

func callFooDoubleChecked() {
	b := FooPreCheck()
	if !b {
		fmt.Println("Should return!")
	}
	c := FooPreCheck()
	if !c {
		return
	}
	FooFunc(G{})
}

func callFooUnChecked() {
	FooPreCheck()
	FooFunc(G{}) // @InvalidCall(funcCond)
}

func callFooResourceCheck() {
	b, e := ResourceCheck()
	if !b || e != nil {
		return
	}
	FooFunc(G{})
}

func main() {
	callFooChecked()
	callFooUnChecked()
	callFooWrongChecked()
	callFooCheckedPathNoReturns()
	callFooResourceCheck()
	callFooDoubleChecked()
}
