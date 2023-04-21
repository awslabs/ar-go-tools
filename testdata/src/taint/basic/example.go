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

func source3() string {
	return "tainted"
}

func source8() string {
	return "tainted"
}

func passing(s1 string, s2 string) string {
	return s1 + s2
}

func test2() {
	s := source3() // @Source(example1)
	s2 := "ok"
	s3 := passing(s, s2)
	s4 := fmt.Sprintf("%s", s3)
	sink1(s4) // tainted data reaches this @Sink(example1)
}

func f(key string, m map[string]string) string {
	for _, x := range m {
		if x == key {
			return fmt.Sprintf("Found key: %s", x)
		}
	}
	return ""
}

func genKey(x int) string {
	if x < 1 {
		return source8() // @Source(example1bis)
	} else {
		return fmt.Sprintf("Ok-%d", x)
	}
}

func test3(n int) {
	m := make(map[string]string)
	for i := 0; i < n; i++ {
		m[genKey(i)] = genKey(n - i)
	}
	taintedStuff := f("Ok-8", m)
	if len(taintedStuff) > 0 {
		sink1(taintedStuff) //@Sink(example1bis)
	}
}
