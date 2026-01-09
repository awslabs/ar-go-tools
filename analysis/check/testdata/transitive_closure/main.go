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
	"strconv"
)

func foo0(a string, b string) string {
	return a + b
}

func fooTop(s string) string {
	return foo0(s, s)
}

type contents struct {
	a string
	b string
	c string
}

func bar(s string) string {
	s2 := fmt.Sprintf("generate-%d", rand.Int())
	c := contents{
		a: s,
		b: s2,
		c: "hello",
	}
	res := fooTop(c.c)
	return res + c.c
}

func baz(s string) string {
	b := "ok"
	a := "ok"
	c := strconv.Itoa(rand.Int())
	for {
		a = b
		b = c
		if rand.Int()%2 == 0 {
			break
		}
	}
	return a
}

func zoo(c contents) string {
	return fooTop(c.a) + c.b
}

// copyString demonstrates flow from one parameter to another
func copyString(a *string, b *string) {
	*a = *b
}

// swapStrings demonstrates bidirectional flow between parameters
func swapStrings(a *string, b *string) {
	temp := *a
	*a = *b
	*b = temp
}

// conditionalCopy demonstrates conditional flow between parameters
func conditionalCopy(a *string, b *string, flag bool) {
	if flag {
		*a = *b
	}
}

// chainedCopy demonstrates transitive flow through multiple parameters
func chainedCopy(a *string, b *string, c *string) {
	*b = *c
	*a = *b
}

// Helper functions for transitive closure testing
func helperCopy(dst *string, src *string) {
	*dst = *src
}

func helperSwap(a *string, b *string) {
	swapStrings(a, b)
}

// Transitive closure test functions - these call other functions
// transitiveViaHelper: calls helperCopy, so b flows to a through the helper
func transitiveViaHelper(a *string, b *string) {
	helperCopy(a, b)
}

// transitiveChain: calls copyString then conditionalCopy
func transitiveChain(a *string, b *string, c *string) {
	copyString(b, c) // c flows to b
	copyString(a, b) // b flows to a
}

// transitiveSwapChain: calls helper that calls swapStrings
func transitiveSwapChain(a *string, b *string) {
	helperSwap(a, b)
}

// transitiveReturn: parameter flows through helper to return value
func transitiveReturn(s *string) string {
	var temp string
	helperCopy(&temp, s)
	return temp
}

func main() {
	fooTop("OI")
	bar("OK")
	zoo(contents{
		a: "a",
		b: "b",
		c: "c",
	})

	// Test parameter-to-parameter flows
	s1, s2, s4 := "hello", "world", "hi"
	copyString(&s1, &s4)
	swapStrings(&s1, &s2)
	conditionalCopy(&s1, &s2, true)
	s3 := "test"
	chainedCopy(&s1, &s2, &s3)

	// Test interprocedural flows
	transitiveViaHelper(&s1, &s2)
	transitiveChain(&s1, &s2, &s3)
	transitiveSwapChain(&s1, &s2)
	transitiveReturn(&s1)
	baz("test")
}
