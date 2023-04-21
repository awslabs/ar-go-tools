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
	random "math/rand"
	"strconv"
)

func genString() string {
	n := random.Int() % 10
	s := ""
	for i := 0; i < n; i++ {
		s += fmt.Sprintf("-%d", i)
	}
	return s
}

func test4() {
	s1 := genString()
	sink1(s1)
	s1 = source3() // @Source(example2)
	sink1(s1)      // this sink is reached by a tainted data @Sink(example2)
	var s []string
	for _, c := range s1 {
		s = append(s, strconv.Itoa(int(c)))
	}
	sink2(s[0]) // this sink is also reached @Sink(example2)
}
