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

func TestSlices(s core.SourceT) {
	slice := []core.SourceT{s}
	core.Sink(slice)                      // @Sink(sl1)
	core.Sink([]core.SourceT{s})          // @Sink(sl1)
	core.Sink([]interface{}{s})           // @Sink(sl1)
	core.Sink([]interface{}{0, "", s})    // @Sink(sl1)
	core.Sink([]interface{}{0, "", s}...) // @Sink(sl1)
}

func TestRangeOverSlice() {
	sources := []core.SourceT{core.Source2()} // @Source(sl2)
	// loop over tainted data
	for i, s := range sources {
		core.Sink(s) // @Sink(sl2)
		core.Sink(i)
	}
}

func TestRangeOverInterfaceSlice() {
	// loop over tainted data
	for i, s := range []interface{}{core.Source2()} { // @Source(sl3)
		core.Sink(s) // @Sink(sl3)
		core.Sink(i)
	}
}

func TestSliceBoundariesAreNotTainted(lo, hi, max int) {
	sources := [4]core.SourceT{core.Source2(), core.Source2()} // @Source(sl4)
	slice := sources[lo:hi:max]
	core.Sink(lo)
	core.Sink(hi)
	core.Sink(max)
	_ = slice
}

func TestSlicedArrayIsTainted() {
	innocs := [1]interface{}{nil}
	slice := innocs[:]
	slice[0] = core.Source2() // @Source(sl5)
	core.Sink(innocs)         // @Sink(sl5)
	_ = slice
}

func TestAllSlices() {
	TestSlices(core.Source2()) // @Source(sl1)
	TestRangeOverSlice()
	TestRangeOverInterfaceSlice()
	TestSliceBoundariesAreNotTainted(0, 1, 2)
	TestSlicedArrayIsTainted()
}
