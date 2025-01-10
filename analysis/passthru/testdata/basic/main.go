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

	"github.com/awslabs/ar-go-tools/analysis/passthru/testdata/basic/core"
)

func exOk() {
	i, err := core.NewCoreInstance()
	if err != nil {
		panic(err)
	}
	msg, err := i.CoreApiOk(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exOk) // TODO false-positive
}

func exInterOk() {
	i, err := core.NewCoreInstance()
	if err != nil {
		panic(err)
	}
	msg, err := i.CoreApiInterOk(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exInterOk) // TODO false-positive
}

func exGlobalOk() {
	i, err := core.NewCoreInstance()
	if err != nil {
		panic(err)
	}
	msg, err := i.CoreApiLeakGlobal(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(msg)
}

func exGlobalLeak() {
	i, err := core.NewCoreInstance()
	if err != nil {
		panic(err)
	}
	msg, err := i.CoreApiLeakGlobal(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg)         // @InvalidAccess(exGlobalLeak)
	fmt.Println(*core.Global) // TODO should this be invalid as well?
}

func exGlobalInterLeak() {
	i, err := core.NewCoreInstance()
	if err != nil {
		panic(err)
	}
	msg, err := i.CoreApiLeakGlobalInter(nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exGlobalInterLeak)
	fmt.Println(*core.Global)
}

func exParamLeak() {
	i, err := core.NewCoreInstance()
	if err != nil {
		panic(err)
	}
	b := new(byte)
	pb := &b                            // @InvalidAccess(exParamLeak)
	msg, err := i.CoreApiLeakParam(&pb) // @InvalidAccess(exParamLeak)
	if err != nil {
		panic(err)
	}
	fmt.Println(*msg) // @InvalidAccess(exParamLeak)
}

func exCoreAllocLeak() {
	i, err := core.NewCoreInstanceLeak() // @CoreAlloc(exCoreAllocLeak) @InvalidAccess(exCoreAllocLeak)
	if err != nil {
		panic(err)
	}
	fmt.Println(i)
	fmt.Println(core.Global)
}

func main() {
	exOk()

	exGlobalOk()
	exGlobalLeak()

	exParamLeak()

	exInterOk()
	exGlobalInterLeak()

	exCoreAllocLeak()
}
