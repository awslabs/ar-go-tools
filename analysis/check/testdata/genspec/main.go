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

func threeArgInter(no *int, a *int, b *int) int {
	x := add2(*a, *a, no)
	x += add2(*a, *b, no)
	*b = x
	return x
}

func add2(a int, b int, no *int) int {
	return a + b
}

func testThreeArgInter() {
	x, y, z := 0, 1, 2
	res := threeArgInter(&x, &y, &z)
	fmt.Println(res) // 5
}

func main() {
	testThreeArgInter()
}
