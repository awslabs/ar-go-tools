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

func TestSourceReceivedFromChannelIsTainted(sources <-chan core.SourceT) {
	s := <-sources
	core.Sink(s) // @Sink(c)
}

func TestChannelIsTaintedWhenSourceIsPlacedOnIt(sources chan<- core.SourceT) {
	sources <- core.Source2() //@Source(c2)
	core.Sink(sources)        // @Sink(c2)
}

func TestValueObtainedFromTaintedChannelIsTainted(c chan interface{}) {
	c <- core.Source2() // @Source(c3)
	s := <-c
	core.Sink(s) // @Sink(c3)
}

func TestChannelIsNoLongerTaintedWhenNilledOut(sources chan core.SourceT) {
	sources <- core.Source2()
	sources = nil
	core.Sink(sources) // -- not tainted! flow sensitivity from ssa
}

func TestRangeOverChan(sources chan core.SourceT) {
	// loop over tainted channel
	for s := range sources {
		core.Sink(s) // @Sink(c)
	}
}

func TestAllChan() {
	c := make(chan core.SourceT, 10)
	c <- core.Source2() // @Source(c)
	TestSourceReceivedFromChannelIsTainted(c)
	TestRangeOverChan(c)

	c2 := make(chan core.SourceT, 10)
	TestChannelIsTaintedWhenSourceIsPlacedOnIt(c2)

	c3 := make(chan interface{}, 10)
	TestValueObtainedFromTaintedChannelIsTainted(c3)

	c4 := make(chan core.SourceT, 10)
	TestChannelIsNoLongerTaintedWhenNilledOut(c4)

}
