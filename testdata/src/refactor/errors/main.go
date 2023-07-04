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
	"os"
)

func main() {
	var a *string
	var err error
	err = nil
	a = nil
	x := 1
	if //goland:noinspection GoBoolExpressions
	x > 0 {
		y := 1
		fmt.Printf("%d, %d, %v\n", y, a, err)
	}
}

// test2 this is some documentations
func test2() {
	f, err := os.Open("main.go")
	// This comment is supposed to appear before if and stay here
	if err != nil {
		return
	} else {
		f.WriteString("example")
		fmt.Printf("Wrote string\n")
		if len(f.Name()) > 2 {
			f.WriteString("another line")
		}

		// This comment should stay here, even though the statement below will change
		f.WriteString("another line")
	}
}
