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

type example struct {
	ptr *string
}

type nestedStruct struct {
	Ex example
	A  string
}

func source2() nestedStruct {
	return nestedStruct{
		Ex: example{},
		A:  "tainted",
	}
}

func sink(_ string) {

}

func generate() *nestedStruct {
	n := source2() // @Source(ex)
	return &n
}

func genFunc(n *nestedStruct) func() string {
	return func() string {
		return "(" + n.A + ")"
	}
}

func delta() {
	n := &nestedStruct{
		Ex: example{},
		A:  "ok",
	}
	f := genFunc(n)
	sink(f()) // @Sink(ex) TODO: reached because pointer analysis is not context sensitive
}

func test() {
	n := generate()
	f := genFunc(n)
	s := f()
	fmt.Printf(s)
}

func main() {
	test()
	delta()
}
