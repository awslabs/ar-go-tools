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

package core

import "fmt"

type CoreInstance struct {
	X []byte
}

func NewCoreInstance() (*CoreInstance, error) {
	return &CoreInstance{X: nil}, fmt.Errorf("error")
}

var CoreAllocGlobal **byte

func NewCoreInstanceLeak() (*CoreInstance, error) {
	alloc := make([]byte, 1)
	*CoreAllocGlobal = &alloc[0]
	return &CoreInstance{X: alloc}, fmt.Errorf("error")
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

var Global **byte

func (i *CoreInstance) CoreApiLeakGlobal(b **byte) (**byte, error) {
	alloc := new(byte) // @CoreAlloc(exGlobalLeak)
	*Global = alloc
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
	*Global = *alloc
}

func (i *CoreInstance) CoreApiLeakParam(b ***byte) (**byte, error) {
	alloc := new(byte) // @CoreAlloc(exParamLeak)
	*b = &alloc
	if b == nil {
		return nil, fmt.Errorf("error")
	}
	return &alloc, nil
}
