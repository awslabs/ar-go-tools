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
	x := new(int) // @Mod(exNoMod)
	*x = 1        // @Mod(exNoMod)
	trackInt(x)   // @ModSource(exNoMod) // prints 1
}

func exModAlias() {
	x := 1 // @Mod(exModAlias)
	y := &x
	*y = 2       // @Mod(exModAlias)
	trackInt(&x) // @ModSource(exModAlias) // prints 2
}

func exModInter() {
	x := 1 // @Mod(exModInter)
	mod(&x)
	trackInt(&x) // @ModSource(exModInter) // prints 2
}

func exNoModStructInit() {
	x := t{}   // @Mod(exNoModStructInit) TODO flag all struct allocations as write
	trackT(&x) // @ModSource(exNoModStructInit) // prints 0
}

func exNoModStructInitField() {
	x := t{}       // @Mod(exNoModStructInitField)
	trackInt(&x.x) // @ModSource(exNoModStructInitField) // prints 0
}

func exNoModStruct() {
	x := t{}   // @Mod(exNoModStruct)
	x.x = 1    // @Mod(exNoModStruct)
	trackT(&x) // @ModSource(exNoModStruct) // prints 1
}

func exModStructAlias() {
	x := t{x: 1} // @Mod(exModStructAlias)
	y := &x
	y.x = 2    // @Mod(exModStructAlias)
	trackT(&x) // @ModSource(exModStructAlias) // prints 2
}

func exModStructInter() {
	x := t{x: 1} // @Mod(exModStructInter)
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
	x := 1         // @Mod(exModStructFieldRef)
	v := tr{x: &x} // @Mod(exModStructFieldRef)
	x++            // @Mod(exModStructFieldRef)
	trackTr(&v)    // @ModSource(exModStructFieldRef) // prints 2
}

func trackTr(v *tr) {
	fmt.Println(*v.x)
}

func exModStructFieldRefInter() {
	x := 1         // @Mod(exModStructFieldRefInter)
	v := tr{x: &x} // @Mod(exModStructFieldRefInter)
	mod(&x)
	trackInt(v.x) // @ModSource(exModStructFieldRefInter) // prints 2
}

func exNoModStructFieldRefAlias() {
	x := 2           // @Mod(exNoModStructFieldRefAlias) // TODO false positive - flow insensitive
	v1 := tr{x: &x}  // @Mod(exNoModStructFieldRefAlias) // TODO ^
	v2 := tr{x: nil} // @Mod(exNoModStructFieldRefAlias) // TODO ^
	v2.x = v1.x      // @Mod(exNoModStructFieldRefAlias) // TODO ^
	y := 1           // @Mod(exNoModStructFieldRefAlias)
	v2.x = &y        // @Mod(exNoModStructFieldRefAlias)    // v2 no longer aliases v1's memory
	trackInt(v2.x)   // @ModSource(exNoModStructFieldRefAlias) // prints 1
}

func exModStructFieldRefAlias() {
	x := 1           // @Mod(exModStructFieldRefAlias)
	v1 := tr{x: &x}  // @Mod(exModStructFieldRefAlias)
	v2 := tr{x: nil} // @Mod(exModStructFieldRefAlias)
	v2.x = v1.x      // @Mod(exModStructFieldRefAlias)
	x++              // @Mod(exModStructFieldRefAlias)
	trackInt(v2.x)   // @ModSource(exModStructFieldRefAlias) prints 2
}

func exModStructFieldRefAliasInter() {
	x := 1           // @Mod(exModStructFieldRefAliasInter)
	v1 := tr{x: &x}  // @Mod(exModStructFieldRefAliasInter)
	v2 := tr{x: nil} // @Mod(exModStructFieldRefAliasInter)
	v2.x = v1.x      // @Mod(exModStructFieldRefAliasInter)
	mod(&x)
	trackInt(v2.x) // @ModSource(exModStructFieldRefAliasInter) // prints 2
}

func exModStructFieldVal() {
	v := t{x: 1} // @Mod(exModStructFieldVal)
	v.x++        // @Mod(exModStructFieldVal)
	trackT(&v)   // @ModSource(exModStructFieldVal) // prints 2
}

type tracker interface {
	track()
}

type toTrack struct {
	x *int
}

func (t *toTrack) track() {
	fmt.Println(t.x)
}

func exTrackInterface() {
	var v tracker = &toTrack{} // @Mod(exTrackInterface)
	v.track()                  // @ModSource(exTrackInterface)
}

func mod(x *int) {
	*x++ // @Mod(exModInter, exModStructAliasInter, exModStructFieldRefInter, exModStructRefInter, exModStructInter, exModStructFieldRefAliasInter)
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
}

type t struct {
	x int
}

func newT(x int) *t {
	return &t{x: x} // @Mod(exModStructAliasInter, exModStructRefInter)
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
