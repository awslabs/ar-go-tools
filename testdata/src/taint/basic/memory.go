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

type U struct {
	content string
}

type V struct {
	data *U
}

func testAliasingTransitive() {
	testAT1()
	testAT2()
	testAT3()
	testAT4()
	testAT5()
	testAT6()
	testAT7()
}

func testAT1() {
	v := V{&U{"ok"}}
	y := v.data
	x := v.data
	populate(x)
	sink1(y.content) // @Sink(at1)
}

func populate(u *U) {
	u.content = source1() // @Source(at1)
}

func testAT2() {
	v := V{&U{"ok"}}
	x := &(v.data.content)
	AT2_populate(&v)
	AT2_consume(x)
}

func AT2_consume(content *string) {
	sink1(*content) // @Sink(at2)
}

func AT2_populate(v *V) {
	v.data.content = source1() // @Source(at2)
}

type S struct {
	next *S
	v    string
}

func testAT3() {
	a := &S{}
	b := &S{a, "ok"}
	a.v = source1() // @Source(at3)
	AT3_handle(b)
}

func AT3_handle(s *S) {
	sink1(s.next.v) // @Sink(at3)
}

func testAT4() {
	a := &S{}
	b := &S{a, "ok"}
	AT4_handle(b)
	a.v = source1() // tainted after AT4_handle is called.
}

func AT4_handle(s *S) {
	sink1(s.next.v)
}

func testAT5() {
	a := &S{}
	b := map[string]*S{"ok": a}
	a.v = source1() // @Source(at5) --> whole map is tainted here
	AT5_handle(b)
}

func AT5_handle(s map[string]*S) {
	for x, val := range s {
		sink1(x)     // @Sink(at5)
		sink1(val.v) // @Sink(at5)
	}
}

func testAT6() {
	println("AT6")
	v := V{&U{"content"}}
	x := map[string]string{"ok1": "fine"}
	x["ok"] = v.data.content // value is written to map
	AT6_populate(&v)
	AT6_consume(x)
}

func AT6_consume(content map[string]string) {
	for _, val := range content {
		sink1(val) // no taint flows here
	}
}

func AT6_populate(v *V) {
	v.data.content = source1()
}

func testAT7() {
	key := "ok"
	sourceMap := map[*string]string{&key: source1()}
	AT7_consume(&key, sourceMap)
}

func AT7_consume(key *string, sources map[*string]string) {
	delete(sources, key)
	sink1(*key) // The key is not tainted
}
