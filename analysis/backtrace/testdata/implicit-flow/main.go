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

func example1() {
	data := source() // @Source(ex1)
	newData := make([]byte, len(data))
	// loop over tainted data
	for i, b := range data {
		switch b {
		case 0x62: // 'b'
			newData[i] = 0x62
		case 0x61: // 'a'
			newData[i] = 0x61
		case 0x64: // 'd'
			newData[i] = 0x64
		default:
			newData[i] = 0x0
		}
	}

	sink(data) // @Sink(ex1)
	sink(newData)
}

func example2() {
	data := source() // @Source(ex2)
	newData := make([]byte, len(data))
	// loop over tainted data
	for i, b := range data {
		switchByte(b, newData, i)
	}

	sink(newData)
}

func example3() {
	c1 := make(chan []byte)
	c1 <- source()
	c2 := make(chan []byte)
	// select tainted channel
	select {
	case <-c1:
		fmt.Println("tainted channel")
	case <-c2:
		fmt.Println("safe channel")
	}
}

func switchByte(b byte, newData []byte, i int) {
	// branch on tainted data
	switch b {
	case 0x62: // 'b'
		newData[i] = 0x62
	case 0x61: // 'a'
		newData[i] = 0x61
	case 0x64: // 'd'
		newData[i] = 0x64
	default:
		newData[i] = 0x0
	}
}

func main() {
	example1()
	example2()
	example3()
}

func source() []byte {
	return []byte("bad")
}

func sink(b []byte) {
	fmt.Println(string(b))
}
