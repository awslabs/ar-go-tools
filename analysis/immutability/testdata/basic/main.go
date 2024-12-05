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

func exNoMod() {
	x := new(int) // @Alloc(exNoMod)
	*x = 1        // @InvalidWrite(exNoMod)
	trackInt(x)   // @ImmutableArg(exNoMod) // prints 1
}

func exModAlias() {
	x := 1 // @Alloc(exModAlias) @InvalidWrite(exModAlias)
	y := &x
	*y = 2       // @InvalidWrite(exModAlias)
	trackInt(&x) // @ImmutableArg(exModAlias) // prints 2
}

func exModInter() {
	x := 1 // @Alloc(exModInter) // @InvalidWrite(exModInter)
	mod(&x)
	trackInt(&x) // @ImmutableArg(exModInter) // prints 2
}

func exNoModStructInit() {
	x := t{}   // @Alloc(exNoModStructInit)
	trackT(&x) // @ImmutableArg(exNoModStructInit) // prints 0
}

func exNoModStructInitField() {
	x := t{}       // @Alloc(exNoModStructInitField)
	trackInt(&x.x) // @ImmutableArg(exNoModStructInitField) @InvalidRead(exNoModStructInitField) // prints 0
}

func exNoModStruct() {
	x := t{}   // @Alloc(exNoModStruct)
	x.x = 1    // @InvalidWrite(exNoModStruct)
	trackT(&x) // @ImmutableArg(exNoModStruct) // prints 1
}

func exModStructAlias() {
	x := t{x: 1} // @Alloc(exModStructAlias) @InvalidWrite(exModStructAlias)
	y := &x
	y.x = 2    // @InvalidWrite(exModStructAlias)
	trackT(&x) // @ImmutableArg(exModStructAlias) // prints 2
}

func exModStructInter() {
	x := t{x: 1} // @Alloc(exModStructInter) @InvalidWrite(exModStructInter)
	mod(&x.x)    // @InvalidRead(exModStructInter)
	trackT(&x)   // @ImmutableArg(exModStructInter) // prints 2
}

func exModStructRefInter() {
	x := 1
	v := newT(x)
	xptr := getXPtr(v)
	mod(xptr) // @InvalidRead(exModStructRefInter)
	trackT(v) // @ImmutableArg(exModStructRefInter) // prints 2
}

func exModStructAliasInter() {
	x := 1
	v1 := newT(x)
	v2 := newT(x)
	v2 = v1
	mod(&v2.x) // @InvalidRead(exModStructAliasInter)
	trackT(v1) // @ImmutableArg(exModStructAliasInter) // prints 2
}

func exModStructFieldRef() {
	x := 1         // @Alloc(exModStructFieldRef) @InvalidWrite(exModStructFieldRef)
	v := tr{x: &x} // @Alloc(exModStructFieldRef) @InvalidRead(exModStructFieldRef)
	x++            // @InvalidWrite(exModStructFieldRef) @InvalidRead(exModStructFieldRef)
	trackTr(&v)    // @ImmutableArg(exModStructFieldRef) // prints 2
}

func exModStructFieldRefInter() {
	x := 1         // @Alloc(exModStructFieldRefInter) @InvalidWrite(exModStructFieldRefInter)
	v := tr{x: &x} // @Alloc(exModStructFieldRefInter) @InvalidRead(exModStructFieldRefInter)
	mod(&x)        // @InvalidRead(exModStructFieldRefInter)
	trackTr(&v)    // @ImmutableArg(exModStructFieldRefInter) // prints 2
}

func trackTr(v *tr) {
	fmt.Println(*v.x) // @InvalidRead(exModStructFieldRef, exModStructFieldRefInter, exModStructFieldRefGetter)
}

func exModStructFieldRefGetter() {
	x := 1         // @Alloc(exModStructFieldRefGetter) @InvalidWrite(exModStructFieldRefGetter)
	v := tr{x: &x} // @Alloc(exModStructFieldRefGetter) @InvalidRead(exModStructFieldRefGetter)
	xval := v.X()
	xptr := v.XPtr()
	fmt.Println(xval) // @Alloc(exModStructFieldRefGetter) @InvalidRead(exModStructFieldRefGetter) // prints 1
	fmt.Println(xptr) // @Alloc(exModStructFieldRefGetter) @InvalidRead(exModStructFieldRefGetter) // prints 1
	mod(&x)           // @InvalidRead(exModStructFieldRefGetter)
	trackTr(&v)       // @ImmutableArg(exModStructFieldRefGetter) // prints 2
}

func exNoModStructFieldRefAlias() {
	x := 2           // @Alloc(exNoModStructFieldRefAlias) @InvalidWrite(exNoModStructFieldRefAlias) // TODO false positive - flow insensitive
	v1 := tr{x: &x}  // @Alloc(exNoModStructFieldRefAlias) @InvalidRead(exNoModStructFieldRefAlias) // TODO ^
	v2 := tr{x: nil} // @Alloc(exNoModStructFieldRefAlias) @InvalidRead(exNoModStructFieldRefAlias) // TODO ^
	v2.x = v1.x      // @InvalidRead(exNoModStructFieldRefAlias)
	y := 1           // @Alloc(exNoModStructFieldRefAlias) @InvalidWrite(exNoModStructFieldRefAlias)
	v2.x = &y        // @InvalidRead(exNoModStructFieldRefAlias)  // v2 no longer aliases v1's memory
	trackInt(v2.x)   // @ImmutableArg(exNoModStructFieldRefAlias) @InvalidRead(exNoModStructFieldRefAlias) // prints 1
}

func exModStructFieldRefAlias() {
	x := 1           // @Alloc(exModStructFieldRefAlias) @InvalidWrite(exModStructFieldRefAlias)
	v1 := tr{x: &x}  // @Alloc(exModStructFieldRefAlias) @InvalidRead(exModStructFieldRefAlias)
	v2 := tr{x: nil} // @Alloc(exModStructFieldRefAlias) @InvalidRead(exModStructFieldRefAlias) // TODO false-positive: context-insensitivity
	v2.x = v1.x      // @InvalidRead(exModStructFieldRefAlias)
	x++              // @InvalidWrite(exModStructFieldRefAlias) @InvalidRead(exModStructFieldRefAlias)
	trackInt(v2.x)   // @ImmutableArg(exModStructFieldRefAlias) @InvalidRead(exModStructFieldRefAlias) prints 2
}

func exModStructFieldRefAliasInter() {
	x := 1           // @Alloc(exModStructFieldRefAliasInter) @InvalidWrite(exModStructFieldRefAliasInter)
	v1 := tr{x: &x}  // @Alloc(exModStructFieldRefAliasInter) @InvalidRead(exModStructFieldRefAliasInter)
	v2 := tr{x: nil} // @Alloc(exModStructFieldRefAliasInter) @InvalidRead(exModStructFieldRefAliasInter) // TODO false-positive: context-insensitivity
	v2.x = v1.x      // @InvalidRead(exModStructFieldRefAliasInter)
	mod(&x)          // @InvalidRead(exModStructFieldRefAliasInter)
	trackInt(v2.x)   // @ImmutableArg(exModStructFieldRefAliasInter) @InvalidRead(exModStructFieldRefAliasInter) // prints 2
}

func exModStructFieldVal() {
	v := t{x: 1} // @Alloc(exModStructFieldVal) @InvalidWrite(exModStructFieldVal)
	v.x++        // @InvalidWrite(exModStructFieldVal) @InvalidRead(exModStructFieldVal)
	trackT(&v)   // @ImmutableArg(exModStructFieldVal) // prints 2
}

type tracker interface {
	track()
	getX() *int
}

type toTrack struct {
	x int
}

func (t *toTrack) getX() *int {
	return &t.x // @InvalidRead(exModTrackInterface)
}

func (t *toTrack) track() {
	fmt.Println(t.x) // @InvalidRead(exTrackInterface, exModTrackInterface)
}

func exTrackInterface() {
	var v tracker = &toTrack{} // @Alloc(exTrackInterface)
	v.track()                  // @ImmutableArg(exTrackInterface) // prints 0
}

func exModTrackInterface() {
	var v tracker = &toTrack{} // @Alloc(exModTrackInterface)
	x := v.getX()
	*x = 1    // @InvalidWrite(exModTrackInterface)
	v.track() // @ImmutableArg(exModTrackInterface) // prints 1
}

func exModClosure() {
	x := new(int) // @Alloc(exModClosure) @InvalidRead(exModClosure)
	f := func() {
		*x = 1 // @InvalidWrite(exModClosure) @InvalidRead(exModClosure)
	}
	f()
	trackInt(x) // @ImmutableArg(exModClosure) @InvalidRead(exModClosure) // prints 1
}

func exModClosureInter() {
	x := new(int) // @Alloc(exModClosureInter) @InvalidRead(exModClosureInter)
	f := func() {
		mod(x) // @InvalidRead(exModClosureInter)
	}
	f()
	trackInt(x) // @ImmutableArg(exModClosureInter) @InvalidRead(exModClosureInter) // prints 1
}

func mod(x *int) {
	*x++ // @InvalidWrite(exModInter, exModStructAliasInter, exModStructFieldRefInter, exModStructRefInter, exModStructFieldRefGetter, exModStructInter, exModStructFieldRefAliasInter, exModClosureInter) @InvalidRead(exModStructRefInter, exModStructFieldRefInter, exModStructFieldRefAliasInter, exModStructInter, exModStructAliasInter, exModInter, exModClosureInter, exModStructFieldRefGetter)
}

func main() {
	fmt.Println("exNoMod")
	exNoMod()
	fmt.Println("exModAlias")
	exModAlias()
	fmt.Println("exModInter")
	exModInter()
	fmt.Println("exNoModStruct")
	exNoModStruct()
	fmt.Println("exNoModStructInit")
	exNoModStructInit()
	fmt.Println("exNoModStructInitField")
	exNoModStructInitField()
	fmt.Println("exModStructAlias")
	exModStructAlias()
	fmt.Println("exModStructInter")
	exModStructInter()
	fmt.Println("exModStructRefInter")
	exModStructRefInter()
	fmt.Println("exModStructAliasInter")
	exModStructAliasInter()
	fmt.Println("exModStructFieldRef")
	exModStructFieldRef()
	fmt.Println("exModStructFieldRefGetter")
	exModStructFieldRefGetter()
	fmt.Println("exModStructFieldRefInter")
	exModStructFieldRefInter()
	fmt.Println("exNoModStructFieldRefAlias")
	exNoModStructFieldRefAlias()
	fmt.Println("exModStructFieldRefAlias")
	exModStructFieldRefAlias()
	fmt.Println("exModStructFieldRefAliasInter")
	exModStructFieldRefAliasInter()
	fmt.Println("exModStructFieldVal")
	exModStructFieldVal()
	fmt.Println("exTrackInterface")
	exTrackInterface()
	fmt.Println("exModTrackInterface")
	exModTrackInterface()
	fmt.Println("exModClosure")
	exModClosure()
	fmt.Println("exModClosureInter")
	exModClosureInter()
}

type t struct {
	x int
}

func newT(x int) *t {
	return &t{x: x} // @Alloc(exModStructAliasInter, exModStructRefInter) @InvalidWrite(exModStructAliasInter, exModStructRefInter) @InvalidRead(exModStructAliasInter, exModStructRefInter)
}

type tr struct {
	x *int
}

func (v *tr) X() int {
	return *v.x // @InvalidRead(exModStructFieldRefGetter)
}

func (v *tr) XPtr() *int {
	return v.x // @InvalidRead(exModStructFieldRefGetter)
}

func getXPtr(v *t) *int {
	return &v.x // @InvalidRead(exModStructRefInter)
}

func trackInt(x *int) {
	fmt.Println(*x) // @InvalidRead(exNoMod, exModAlias, exModInter, exNoModStructFieldRefAlias, exModStructFieldRefAlias, exModStructFieldRefAliasInter, exModClosure, exModClosureInter, exNoModStructInitField, exNoModStructFieldRefAlias)
}

func trackT(v *t) {
	fmt.Println(v.x) // @InvalidRead(exNoModStruct, exNoModStructInit, exModStructRefInter, exModStructRefInter, exModStructInter, exModStructAlias, exModStructAliasInter, exModStructFieldVal)
}
