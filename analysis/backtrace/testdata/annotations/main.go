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
)

//argot:function BacktracePoint(test1)
func sourceValue() int {
	return rand.Int()
}

//argot:function BacktracePoint(test2)
func modifyValue(x int) int {
	return x * 2
}

func processValue(x int) int {
	return modifyValue(x) + 1 // Should backtrace through this call
}

func main() {
	val := sourceValue()        // @BacktracePoint(test1)
	result := processValue(val) // Should backtrace through this
	fmt.Printf("Result: %d\n", result)

	directVal := modifyValue(42) // @BacktracePoint(test2)
	fmt.Printf("Direct: %d\n", directVal)
}
