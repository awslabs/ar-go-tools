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

// This is a simple example that doesn't do much, but also does not use any goroutines
func testSelect1() {
	x := R("ok")
	var y R
	c := make(chan R, 10)
	quit := make(chan int)

	for {
		select {
		case c <- x:
			x = source2() // @Source(test1)
		case y = <-c:
			sink(y) // @Sink(test1)
		case <-quit:
			fmt.Println("quit")
			return
		}
	}

}

func testSelect2() {
	x := R("ok")
	var y R
	var z R
	c1 := make(chan R, 10)
	c2 := make(chan R, 10)
	quit := make(chan int)

	for {
		select {
		case c2 <- y:
			fmt.Println("Ok")
		case y = <-c1:
			sink(y) // @Sink(test2)
		case z = <-c2:
			sink(z) // @Sink(test2)
		case c1 <- x:
			x = source2() // @Source(test2)
		case <-quit:
			fmt.Println("quit")
			return
		}
	}
}

func testSelect3() {
	s := R("ok")
	x := &s
	var y *R
	c := make(chan *R, 10)
	quit := make(chan int)

	for {
		select {
		case y = <-c:
			sink(*y) // @Sink(test3)
			set(x)
		case c <- x:
			fmt.Println("ok")
		case <-quit:
			fmt.Println("quit")
			return
		}
	}

}

func set(x *R) {
	*x = source2() // @Source(test3)
}

func main() {
	testSelect1()
	testSelect2()
	testSelect3()
}
