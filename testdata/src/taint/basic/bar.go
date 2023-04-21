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

func source2(x int) string {
	s := ""
	for i := 0; i < x; i++ {
		s += "a"
	}
	return s
}

func producer(x chan string) {
	x <- source2(10) // @Source(line14)
}

func producerCaller(b chan string) {
	b <- "ok"
	producer(b)
}

func consumer(b chan string) {
	sink2(<-b) // want "reached by tainting call on line 14" @Sink(line14)
}

func test1() {
	b := make(chan string, 3)
	producerCaller(b)
	fmt.Printf("Example: %s, %s", <-b, "ok")
	consumer(b)
}

func sink2(s string) {
	fmt.Printf("Log: %s", s)
}
