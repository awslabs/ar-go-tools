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

func f1() {
	f2()
	f4()
	f3()
}

func f2() {
	f1()
}

func f3() {
	f2()
}

func f4() {
	f5()
}

func f5() {
	f1()
}

func g() {
	g1()
	g2()
	g3()
}

func g1() {
	f1()
}

func g2() {
	g()
}

func g3() {
	g2()
}

func main() {
	f1()
	g()
}
