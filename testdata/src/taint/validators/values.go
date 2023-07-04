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

import "strings"

// Example 14: validation on a reference

func example14validateOnReference() {
	b := source1() // @Source(ex14)
	a := &b
	if Validate(*a) {
		sink1(*a)
	}
}

// Example 15 validation on a reference

func example15validateOnReference2() {
	b := source1() // @Source(ex15)
	a := &b
	c := &a
	if Validate(**c) {
		sink1(**c)
	}
}

// Example 16: validation on a reference

func example16validateOnReference3() {
	b := source1() // @Source(ex16)
	a := &b
	c := &a
	if Validate(*a) {
		sink1(**c)
	}
}

// Example 17: validation on a reference

func example17validateOnReference4() {
	b := "c"
	a := &b
	c := &a
	b = b + source1() // @Source(ex17bis)
	d := "s"
	a = &d
	if Validate(**c) {
		sink1(b) // @Sink(ex17bis)
	}
}

// Example 18: validation on an intermediate reference

type B struct {
	stringPtr *string
}

func NewB(value string) *B {
	a := value
	return &B{stringPtr: &a}
}

func (b *B) ValidateSelf() bool {
	return !strings.ContainsAny(*(b.stringPtr), "xy")
}

func example18validateOnFieldReference() {
	b := NewB(source1()) //@Source(ex18)
	if b.ValidateSelf() {
		s := *b.stringPtr
		sink1(s) // @Sink(ex18) This is not supported for now
	}
}
