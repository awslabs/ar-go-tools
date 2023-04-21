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

func Foo(x int) int {
	return x*x + 1
}

func Bar(x int) []int {
	// ssa block 0
	s := make([]int, x)
	// ssa block 3
	for i := 0; i < x; i++ {
		// ssa block 1
		s[i] = Foo(i)
		if s[i] > 9 {
			// ssa block 4
			continue
		} else {
			// ssa block 5
			// ssa block 8
			for j := 0; j < x; j++ {
				// ssa block 6
				s[i] += 1
			}
			// ssa block 7
			return s
		}
	}
	// ssa block 2
	return s
}

func main() {
	c := make(chan int, 3)
	c <- 1
	c <- 2
	c <- 3
	for x := range c {
		for _, x := range Bar(x) {
			fmt.Println(x)
		}
	}
}
