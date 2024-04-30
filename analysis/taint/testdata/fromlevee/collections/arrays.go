// Copyright 2020 Google LLC
// Modifications Copyright Amazon.com, Inc. or its affiliates
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

package collections

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func TestArrayLiteralContainingSourceIsTainted(s core.SourceT) {
	tainted := [1]core.SourceT{s}
	core.Sink(tainted) // @Sink(ar2)
}

func TestArrayIsTaintedWhenSourceIsInserted(s core.SourceT) {
	arr := [2]interface{}{nil, nil}
	arr[0] = s
	core.Sink(arr) // @Sink(ar1)
}

func TestValueObtainedFromTaintedArrayIsTainted(s core.SourceT) {
	arr := [2]interface{}{nil, nil}
	arr[0] = s
	core.Sink(arr[1]) // @Sink(ar3)
}

func TestArrayRemainsTaintedWhenSourceIsOverwritten(s core.SourceT) {
	arr := [2]interface{}{s, nil}
	arr[0] = nil
	core.Sink(arr) // @Sink(ar4)
}

func TestRangeOverArray() {
	sources := [1]core.Container{{Data: core.Source1()}} // @Source(ar5)
	for i, s := range sources {
		core.Sink(s.Data) // @Sink(ar5)
		core.Sink(i)
	}
}

func TestAllArrays() {
	TestArrayIsTaintedWhenSourceIsInserted(core.Source2())         // @Source(ar1)
	TestArrayLiteralContainingSourceIsTainted(core.Source2())      // @Source(ar2)
	TestValueObtainedFromTaintedArrayIsTainted(core.Source2())     // @Source(ar3)
	TestArrayRemainsTaintedWhenSourceIsOverwritten(core.Source2()) // @Source(ar4)
	TestRangeOverArray()
}
