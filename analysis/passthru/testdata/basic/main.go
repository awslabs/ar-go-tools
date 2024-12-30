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

type CoreInstance struct {
	X []byte
}

func NewCoreInstance() *CoreInstance {
	return &CoreInstance{X: nil}
}

func (i *CoreInstance) CoreApiOk(b **byte) (**byte, error) {
	alloc := new(byte) // @CoreAlloc(exOk)
	if alloc == nil {
		return nil, fmt.Errorf("error")
	}
	return &alloc, nil
}

func (i *CoreInstance) CoreApiInterOk(b **byte) (**byte, error) {
	alloc := doAlloc()
	if alloc == nil {
		return nil, fmt.Errorf("error")
	}
	return &alloc, nil
}

func doAlloc() *byte {
	alloc := new(byte) // @CoreAlloc(exInterOk)
	return alloc
}

var global **byte

func (i *CoreInstance) CoreApiLeakGlobal(b **byte) (**byte, error) {
	alloc := new(byte) // @CoreAlloc(exGlobalLeak)
	*global = alloc
	if b == nil {
		return nil, fmt.Errorf("error")
	}
	return &alloc, nil
}

func (i *CoreInstance) CoreApiLeakGlobalInter(b **byte) (**byte, error) {
	alloc := new(byte) // @CoreAlloc(exGlobalInterLeak)
	leakGlobal(&alloc)
	if b == nil {
		return nil, fmt.Errorf("error")
	}
	return &alloc, nil
}

func leakGlobal(alloc **byte) {
	*global = *alloc
}

func (i *CoreInstance) CoreApiLeakParam(b ***byte) (**byte, error) {
	alloc := new(byte) // @CoreAlloc(exParamLeak)
	*b = &alloc
	if b == nil {
		return nil, fmt.Errorf("error")
	}
	return &alloc, nil
}

func exOk() {
	i := NewCoreInstance()
	msg, err := i.CoreApiOk(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exOk) // TODO false-positive
}

func exInterOk() {
	i := NewCoreInstance()
	msg, err := i.CoreApiInterOk(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exInterOk) // TODO false-positive
}

func exGlobalOk() {
	i := NewCoreInstance()
	msg, err := i.CoreApiLeakGlobal(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(msg)
}

func exGlobalLeak() {
	i := NewCoreInstance()
	msg, err := i.CoreApiLeakGlobal(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg)    // @InvalidAccess(exGlobalLeak)
	fmt.Println(*global) // TODO should this be invalid as well?
}

func exGlobalInterLeak() {
	i := NewCoreInstance()
	msg, err := i.CoreApiLeakGlobalInter(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exGlobalInterLeak)
	fmt.Println(*global)
}

func exParamLeak() {
	i := NewCoreInstance()
	b := new(byte)
	pb := &b                            // @InvalidAccess(exParamLeak)
	msg, err := i.CoreApiLeakParam(&pb) // @InvalidAccess(exParamLeak)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exParamLeak)
}

func main() {
	exOk()

	exGlobalOk()
	exGlobalLeak()

	exParamLeak()

	exInterOk()
	exGlobalInterLeak()
}
