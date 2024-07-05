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

type _S struct {
	Data string
	Id   int
}

func testChannelReadAsSource() {
	testChan1()
	testChan2()
	testChan3()
	testChan4()
}

// TEST 1: channel populated in goroutine, reading from channel is marked as source, channel has pointer values
// reading in a range loop

func testChan1() {
	c := make(chan *_S)
	go fillChan(c)
	for elt := range c { // @Source(chan1)
		toSink(elt.Data)
	}
}

func fillChan(c chan *_S) {
	c <- &_S{"Hello", 0}
	c <- &_S{"world!", 0}
}

func toSink(s string) {
	sink1(s) // @Sink(chan1)
}

// TEST 2: channel populated in goroutine, reading from channel is marked as source, channel has non-pointer values
// reading in a range loop

func testChan2() {
	c := make(chan _S)
	go fillChan2(c)
	for elt := range c { // @Source(chan2)
		consume2(elt.Data)
	}
}

func fillChan2(c chan _S) {
	c <- _S{"Hello", 0}
	c <- _S{"world!", 0}
}

func consume2(s string) {
	sink1(s) // @Sink(chan2)
}

// TEST 3: channel populated in goroutine, reading from channel is marked as source, channel has non-pointer values
// reading directly

func testChan3() {
	c := make(chan _S)
	go fillChan2(c)
	x := <-c      // @Source(chan3, chan31)
	sink1(x.Data) // @Sink(chan3)
	x = <-c       // @Source(chan3bis)
	sink1(x.Data) // @Sink(chan3bis, chan31)
}

// TEST 4: channel populated in goroutine, reading from channel is marked as source, channel has pointer values
// reading directly

func testChan4() {
	c := make(chan *_S)
	go fillChan(c)
	x := <-c      // @Source(chan4, chan41)
	sink1(x.Data) // @Sink(chan4)
	x = <-c       // @Source(chan4bis)
	sink1(x.Data) // @Sink(chan4bis, chan41)
}
