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
	*x = 1        // @Mod(exNoMod)
	trackInt(x)   // @ModSource(exNoMod) // prints 1
}

func exModAlias() {
	x := 1 // @Alloc(exModAlias) @Mod(exModAlias)
	y := &x
	*y = 2       // @Mod(exModAlias)
	trackInt(&x) // @ModSource(exModAlias) // prints 2
}

func exModInter() {
	x := 1 // @Alloc(exModInter) // @Mod(exModInter)
	mod(&x)
	trackInt(&x) // @ModSource(exModInter) // prints 2
}

func exNoModStructInit() {
	x := t{}   // @Alloc(exNoModStructInit)
	trackT(&x) // @ModSource(exNoModStructInit) // prints 0
}

func exNoModStructInitField() {
	x := t{}       // @Alloc(exNoModStructInitField)
	trackInt(&x.x) // @ModSource(exNoModStructInitField) // prints 0
}

func exNoModStruct() {
	x := t{}   // @Alloc(exNoModStruct)
	x.x = 1    // @Mod(exNoModStruct)
	trackT(&x) // @ModSource(exNoModStruct) // prints 1
}

func exModStructAlias() {
	x := t{x: 1} // @Alloc(exModStructAlias) @Mod(exModStructAlias)
	y := &x
	y.x = 2    // @Mod(exModStructAlias)
	trackT(&x) // @ModSource(exModStructAlias) // prints 2
}

func exModStructInter() {
	x := t{x: 1} // @Alloc(exModStructInter) @Mod(exModStructInter)
	mod(&x.x)
	trackT(&x) // @ModSource(exModStructInter) // prints 2
}

func exModStructRefInter() {
	x := 1
	v := newT(x)
	xptr := getXPtr(v)
	mod(xptr)
	trackT(v) // @ModSource(exModStructRefInter) // prints 2
}

func exModStructAliasInter() {
	x := 1
	v1 := newT(x)
	v2 := newT(x)
	v2 = v1
	mod(&v2.x)
	trackT(v1) // @ModSource(exModStructAliasInter) // prints 2
}

func exModStructFieldRef() {
	x := 1         // @Alloc(exModStructFieldRef) @Mod(exModStructFieldRef)
	v := tr{x: &x} // @Alloc(exModStructFieldRef)
	x++            // @Mod(exModStructFieldRef)
	trackTr(&v)    // @ModSource(exModStructFieldRef) // prints 2
}

func exModStructFieldRefInter() {
	x := 1         // @Alloc(exModStructFieldRefInter) // @Mod(exModStructFieldRefInter)
	v := tr{x: &x} // @Alloc(exModStructFieldRefInter)
	mod(&x)
	trackTr(&v) // @ModSource(exModStructFieldRefInter) // prints 2
}

func trackTr(v *tr) {
	fmt.Println(*v.x)
}

func exNoModStructFieldRefAlias() {
	x := 2           // @Alloc(exNoModStructFieldRefAlias) @Mod(exNoModStructFieldRefAlias) // TODO false positive - flow insensitive
	v1 := tr{x: &x}  // @Alloc(exNoModStructFieldRefAlias) // TODO ^
	v2 := tr{x: nil} // @Alloc(exNoModStructFieldRefAlias) // TODO ^
	v2.x = v1.x
	y := 1         // @Alloc(exNoModStructFieldRefAlias) @Mod(exNoModStructFieldRefAlias)
	v2.x = &y      // v2 no longer aliases v1's memory
	trackInt(v2.x) // @ModSource(exNoModStructFieldRefAlias) // prints 1
}

func exModStructFieldRefAlias() {
	x := 1           // @Alloc(exModStructFieldRefAlias) @Mod(exModStructFieldRefAlias)
	v1 := tr{x: &x}  // @Alloc(exModStructFieldRefAlias)
	v2 := tr{x: nil} // @Alloc(exModStructFieldRefAlias)
	v2.x = v1.x
	x++            // @Mod(exModStructFieldRefAlias)
	trackInt(v2.x) // @ModSource(exModStructFieldRefAlias) prints 2
}

func exModStructFieldRefAliasInter() {
	x := 1           // @Alloc(exModStructFieldRefAliasInter) @Mod(exModStructFieldRefAliasInter)
	v1 := tr{x: &x}  // @Alloc(exModStructFieldRefAliasInter)
	v2 := tr{x: nil} // @Alloc(exModStructFieldRefAliasInter)
	v2.x = v1.x
	mod(&x)
	trackInt(v2.x) // @ModSource(exModStructFieldRefAliasInter) // prints 2
}

func exModStructFieldVal() {
	v := t{x: 1} // @Alloc(exModStructFieldVal) // @Mod(exModStructFieldVal)
	v.x++        // @Mod(exModStructFieldVal)
	trackT(&v)   // @ModSource(exModStructFieldVal) // prints 2
}

type tracker interface {
	track()
	getX() *int
}

type toTrack struct {
	x int
}

func (t *toTrack) getX() *int {
	return &t.x
}

func (t *toTrack) track() {
	fmt.Println(t.x)
}

func exTrackInterface() {
	var v tracker = &toTrack{} // @Alloc(exTrackInterface)
	v.track()                  // @ModSource(exTrackInterface) // prints 0
}

func exModTrackInterface() {
	var v tracker = &toTrack{} // @Alloc(exModTrackInterface)
	x := v.getX()
	*x = 1    // @Mod(exModTrackInterface)
	v.track() // @ModSource(exModTrackInterface) // prints 1
}

func exModClosure() {
	x := new(int) // @Alloc(exModClosure)
	f := func() {
		*x = 1 // @Mod(exModClosure)
	}
	f()
	trackInt(x) // @ModSource(exModClosure) // prints 1
}

func exModClosureInter() {
	x := new(int) // @Alloc(exModClosureInter)
	f := func() {
		mod(x)
	}
	f()
	trackInt(x) // @ModSource(exModClosureInter) // prints 1
}

func mod(x *int) {
	*x++ // @Mod(exModInter, exModStructAliasInter, exModStructFieldRefInter, exModStructRefInter, exModStructInter, exModStructFieldRefAliasInter, exModClosureInter)
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
	return &t{x: x} // @Alloc(exModStructAliasInter, exModStructRefInter) @Mod(exModStructAliasInter, exModStructRefInter)
}

type tr struct {
	x *int
}

func getXPtr(v *t) *int {
	return &v.x
}

func trackInt(x *int) {
	fmt.Println(*x)
}

func trackT(v *t) {
	fmt.Println(v.x)
}
