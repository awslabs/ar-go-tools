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

func (i *CoreInstance) CoreApiOk(b []byte) ([]byte, error) {
	alloc := make([]byte, 5)
	if len(b) == 0 {
		return nil, fmt.Errorf("error")
	}
	return append(alloc, b), nil
}

var global *byte

func (i *CoreInstance) CoreApiLeakGlobal(b []byte) ([]byte, error) {
	alloc := make([]byte, 5)
	global = &alloc[0]
	if len(b) == 0 {
		return nil, fmt.Errorf("error")
	}
	return append(alloc, b...), nil
}

func (i *CoreInstance) CoreApiLeakParam(b *byte) ([]byte, error) {
	alloc := make([]byte, 5)
	b = &alloc[0] // @InvalidWrite(exLeakParamErr)
	if b == nil {
		return nil, fmt.Errorf("error")
	}
	return append(alloc, *b), nil
}

func (i *CoreInstance) CoreApiLeakArg(b []byte) ([]byte, error) {
	alloc := make([]byte, 5)
	if len(b) == 0 {
		return nil, fmt.Errorf("error")
	}
	fmt.Println(alloc) // @InvalidRead(exLeakArgErr)
	return append(alloc, b...), nil
}

func exOk() {
	i := NewCoreInstance()
	b, err := i.CoreApi1([]byte("test"))
	if err != nil {
		panic(err)
	}
	fmt.Println(b)
}

func exLeakGlobalOk() {
	i := NewCoreInstance()
	b, err := i.CoreApiLeakGlobal([]byte("test"))
	if err != nil {
		panic(err)
	}
	fmt.Println(b)
}

func exLeakGlobalErr() {
	i := NewCoreInstance()
	b, err := i.CoreApiLeakGlobal([]byte("test"))
	if err != nil {
		panic(err)
	}
	fmt.Println(b)
	fmt.Println(global) // @InvalidRead(exLeakGlobalErr)
}

func exLeakParam() {
	i := NewCoreInstance()
	b, err := i.CoreApiLeakParam([]byte("test"))
	if err != nil {
		panic(err)
	}
	fmt.Println(b)
}

func main() {
	exOk()
	exLeakGlobalOk()
	exLeakGlobalErr()
}
