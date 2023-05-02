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

func source() string {
	return "tainted-data"
}

func gen() string {
	return "OK"
}

func sink(_ any) {}

func main() {
	TestTuple1()
	TestTuple2()
	TestTuple3()
	TestTuple4()
}

// TestTuple1 is a simple test where only one element of the tuple is tainted

func TestTuple1() {
	x, y := F(source()) // @Source(t1)
	sink(x)             // @Sink(t1)
	sink(y)
}

func F(a string) (string, string) {
	return a + "ok", "fresh"
}

// TestTuple2 tests the case where both elements are tainted

func TestTuple2() {
	x, y := G(source()) // @Source(t2)
	sink(x)             // @Sink(t2)
	sink(y)             // @Sink(t2)
}

func G(a string) (string, string) {
	return a + "ok", "fresh" + a
}

// TestTuple3: tuples + one more function call

func TestTuple3() {
	x, y := F(source()) // @Source(t3)
	CallSink(x, y)
}

func CallSink(x string, y string) {
	sink(x) // @Sink(t3)
	sink(y)
}

// TestTuple4: tuples + closures

func TestTuple4() {
	x, y := closure4(source()) // @Source(t4)
	sink(x)
	sink(y()) // @Sink(t4)
}

func closure4(a string) (string, func() string) {
	b := "(" + a + ")"
	return gen(), func() string { return b }
}
