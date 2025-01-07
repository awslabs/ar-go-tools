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

// NOTE it is expected that this program segfaults when run

type sslice struct {
	f []byte
}

type sval struct {
	f byte
}

func exParamLeak(b **byte) {
	alloc := new(byte) // @CoreAlloc(exParamLeak)
	*b = alloc         // @Escape(exParamLeak)
}

func exParamOk(b *byte) {
	alloc := new(byte) // @CoreAlloc(exParamOk)
	b = alloc
}

func exParamFieldLeak(s *sslice) {
	alloc := make([]byte, 1) // @CoreAlloc(exParamFieldLeak)
	s.f = alloc              // @Escape(exParamFieldLeak)
}

func exParamElemLeak(b **byte) {
	alloc := make([]byte, 1) // @CoreAlloc(exParamElemLeak)
	*b = &alloc[0]           // @Escape(exParamElemLeak)
}

func exParamFieldOk(s *sslice) {
	alloc := make([]byte, 1) // @CoreAlloc(exParamFieldOk)
	s.f[0] = alloc[0]
	alloc[0] = s.f[0]
}

func exArgLeak() {
	alloc := make([]byte, 3) // @CoreAlloc(exArgLeak)
	fmt.Println(alloc)       // @Escape(exArgLeak)
}

func exFreeLeak() {
	alloc := make([]byte, 3) // @CoreAlloc(exFreeLeak) @Escape(exFreeLeak)
	func() {
		fmt.Println(alloc)
	}()
}

var global1 **byte

func exGlobalLeak() {
	alloc := new(byte) // @CoreAlloc(exGlobalLeak)
	fmt.Println(alloc) // @Escape(exGlobalLeak)
	// ^ TODO false-positive: fmt.Println allocates a new slice to which alloc is written
	*global1 = alloc // @Escape(exGlobalLeak)
}

var global2 **byte

func exGlobalElemLeak() {
	alloc := make([]byte, 1) // @CoreAlloc(exGlobalElemLeak)
	*global2 = &alloc[0]     // @Escape(exGlobalElemLeak)
}

var global3 **byte

func exGlobalFieldLeak() {
	alloc := &sval{f: 0x0} // @CoreAlloc(exGlobalFieldLeak)
	*global3 = &alloc.f    // @Escape(exGlobalFieldLeak)
}

func exInterOk() {
	alloc := make([]byte, 1) // @CoreAlloc(exInterOk) // @Escape(exInterOk) // TODO escape false-positive
	doSafe(&alloc)
}

func doSafe(alloc *[]byte) {
	fmt.Println(alloc)
}

func exInterLeak() {
	alloc := make([]byte, 1) // @CoreAlloc(exInterLeak) // @Escape(exInterLeak) // TODO escape false-positive
	doUnsafeCall(&alloc)
}

func doUnsafeCall(alloc *[]byte) {
	doSafe(alloc)
	doUnsafe(alloc)
}

var global4 **byte

func doUnsafe(alloc *[]byte) {
	*global4 = &((*alloc)[0]) // @Escape(exInterLeak)
}

func main() {
	var b **byte
	exParamLeak(b)
	exParamOk(*b)
	exParamElemLeak(b)
	var s *sslice
	exParamFieldLeak(s)
	exParamFieldOk(s)

	exArgLeak()

	exFreeLeak()

	exGlobalLeak()
	exGlobalElemLeak()
	exGlobalFieldLeak()

	exInterOk()
	exInterLeak()
}
