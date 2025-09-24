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

import "fmt"

type Stringer interface {
	String() string
}

type TaintedString struct {
	value string
}

func (t TaintedString) String() string {
	return t.value
}

type CleanInt struct {
	value int
}

func (c CleanInt) String() string {
	return fmt.Sprintf("%d", c.value)
}

func processWithTypeSwitch(x interface{}) {
	// Both tainted sources flow to each sink because we lose the underlying imeplementation
	// when converting to an interface.
	switch v := x.(type) {
	case Stringer:
		sink(v.String()) // @Sink(typeswitch,typeswitch2)
	case string:
		sink(v) // @Sink(typeswitch2,typeswitch)
	default:
		sink("unknown")
	}
}

func testTypeSwitch() {
	tainted := TaintedString{value: source()} // @Source(typeswitch)
	clean := CleanInt{value: 42}
	taintedStr := source() // @Source(typeswitch2)

	processWithTypeSwitch(tainted)    // should reach sink
	processWithTypeSwitch(clean)      // should not reach sink
	processWithTypeSwitch(taintedStr) // should reach sink
}
