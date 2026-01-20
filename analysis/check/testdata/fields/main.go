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

type simpleContainer struct {
	field data
}

type data struct {
	value int
}

func incFieldBy(c *simpleContainer, n int) {
	c.field.value += n
}

func testIncFieldBy() {
	x := &simpleContainer{field: data{0}}
	incFieldBy(x, 5)
	fmt.Printf("x.field:%v\n", x.field.value)
}

type container struct {
	field *data
	other *data
}

func propagateFieldsField(src, dst *container) {
	dst.field = &data{value: src.field.value + src.field.value}
}

func propagateFieldsOther(src, dst *container) {
	dst.other = &data{value: src.other.value + src.other.value}
}

func propagateFieldsBoth(src, dst *container) {
	dst.other = &data{value: src.field.value + src.other.value}
}

func addVals(a, b *data) *data {
	return &data{value: a.value + b.value}
}

func testFieldPropagationField() {
	x := &container{field: &data{0}, other: &data{1}}
	y := &container{field: &data{2}, other: &data{2}}
	propagateFieldsField(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
}

func testFieldPropagationOther() {
	x := &container{field: &data{0}, other: &data{1}}
	y := &container{field: &data{2}, other: &data{2}}
	propagateFieldsOther(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
}

func testFieldPropagationBoth() {
	x := &container{field: &data{0}, other: &data{1}}
	y := &container{field: &data{2}, other: &data{2}}
	propagateFieldsBoth(x, y)
	fmt.Printf(
		"x.field:%v x.other:%v, y.field:%v y.other:%v\n",
		x.field.value, x.other.value, y.field.value, y.other.value)
}

type tree struct {
	n     int
	right *tree
	left  *tree
}

func incRight(t tree, n int) {
	t.right.n += n
}

func testIncRight() {
	x := tree{n: 1, right: &tree{}, left: nil}
	fmt.Println("x.right:", x.right.n)
	// x.right: 2
	incRight(x, 2)
	fmt.Println("x.right:", x.right.n)
	// x.right: 2
}

func main() {
	testIncFieldBy()
	testFieldPropagationField()
	testFieldPropagationOther()
	testFieldPropagationBoth()
	testIncRight()
}
