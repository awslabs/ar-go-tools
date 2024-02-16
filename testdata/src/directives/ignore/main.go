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

type v struct {
	val string
}

func source1() string {
	return "tainted"
}

func sink1(_ string) {
}

func main() {
	a := "hello"
	if len(a) < 5 {
		a = "hi"
	}
	source := source1() + a // @Source(ex)
	x := &v{val: source}
	y := x.val + "1"
	sink1(y) //argot:ignore
}
