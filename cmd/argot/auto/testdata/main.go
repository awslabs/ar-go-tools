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
	"math/rand"
	"strconv"
)

type MyStruct struct {
	MyField int
	Other   string
}

const MyValue = 0

func Source(i int) string {
	return strconv.Itoa(i) + "-tainted"
}

func Sink(x string) {
	fmt.Printf(x)
}

func Back(arg string) {
	fmt.Println(arg)
}

func main() {
	// Source flows to sink
	Sink(Source(rand.Int()))
	// Backtrace
	Back(Source(rand.Int()))

	// Struct initialization
	var m MyStruct
	Sink(m.Other)
}
