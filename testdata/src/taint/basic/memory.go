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

type X struct {
	data *Y
}

type Y struct {
	content *S
}

func testAliasingTransitive() {
	testAT1()
	testAT2()
	testAT3()
	testAT4()
	testAT5()
	testAT6()
	testAT7()
	testAT8()
	testAT9()
	testAT10()
	testAT11()
	testAT12()
	testAT13()
	testAT14()
	testAT15()
	testAT16()
	testAT17()
	testAT18()
	testAT19()
	testAT20()
	testAT21()
	testAT22()
	testAT23()
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

func testAT8() {
	println("AT8")
	v := V{&U{"content"}}
	x := map[string]*U{"ok1": &U{"content2"}}
	x["ok"] = v.data
	AT8_populate(&v)
	AT8_consume(x)
}

func AT8_consume(content map[string]*U) {
	for _, val := range content {
		sink1(val.content) // @Sink(at8)
	}
}

func AT8_populate(v *V) {
	v.data.content = source1() // @Source(at8)
}

func testAT9() {
	println("AT9")
	v := V{&U{"content"}}
	x := []*U{&U{"content2"}}
	x[0] = v.data
	AT9_populate(&v)
	AT9_consume(x)
}

func AT9_consume(content []*U) {
	for _, val := range content {
		sink1(val.content) // @Sink(at9)
	}
}

func AT9_populate(v *V) {
	v.data.content = source1() // @Source(at9)
}

func testAT10() {
	a := &S{}
	b := []*S{a}
	a.v = source1() // @Source(at10) --> whole slice is tainted here
	AT10_handle(b)
}

func AT10_handle(s []*S) {
	for _, val := range s {
		sink1(val.v) // @Sink(at10)
	}
}

func testAT11() {
	println("AT11")
	a := &S{}
	b := []S{*a} // value is stored in slice, not pointer
	a.v = source1()
	AT11_handle(b)
}

func AT11_handle(s []S) {
	for _, val := range s {
		sink1(val.v) // no tainted data reaches here.
	}
}

func testAT12() {
	println("AT12")
	a := &S{}
	b := &S{}
	a.next = b
	c := []*S{a}
	b.v = source1() // @Source(at12) --> whole slice is tainted here
	AT12_handle(c)
}

func AT12_handle(s []*S) {
	for _, val := range s {
		sink1(val.next.v) // @Sink(at12)
	}
}

func testAT13() {
	println("AT13")
	a := &S{}
	b := &S{}
	a.next = b
	c := []*S{a}
	d := &S{v: source1()} // @Source(at13)
	b.next = d
	AT13_handle(c)
}

func AT13_handle(s []*S) {
	for _, val := range s {
		sink1(val.next.v) // @Sink(at13) - imprecision, here the entire val is considered tainted
	}
}

func testAT14() {
	println("AT14")
	v := V{&U{"content"}}
	x := make(chan string, 10)
	x <- "fine"
	x <- v.data.content // value is written to channel
	AT14_populate(&v)
	AT14_consume(x)
}

func AT14_consume(content chan string) {
	sink1((<-content))
}

func AT14_populate(v *V) {
	v.data.content = source1()
}

func testAT15() {
	println("AT15")
	v := V{&U{"content"}}
	x := make(chan *U, 10)
	x <- &U{"fine"}
	x <- v.data // pointer to U into channel
	AT15_populate(&v)
	AT15_consume(x)
}

func AT15_consume(c chan *U) {
	sink1((<-c).content) // @Sink(at15)
	sink1((<-c).content) // @Sink(at15)
}

func AT15_populate(v *V) {
	v.data.content = source1() // @Source(at15)
}

func testAT16() {
	println("AT16")
	a := &S{}
	b := make(chan *S, 10)
	b <- a
	a.v = source1() // @Source(at16)
	AT16_handle(b)
}

func AT16_handle(s chan *S) {
	sink1((<-s).v) // @Sink(at16)
}

func testAT17() {
	println("AT17")
	a := &S{next: &S{}}
	b := make(chan *S, 10)
	b <- a
	a.v = "ok"
	a.next.v = source1() // @Source(at17)
	AT17_handle(b)
}

func AT17_handle(s chan *S) {
	sink1((<-s).v) // @Sink(at17)
}

func testAT18() {
	s := generateData18()
	sink1(s.v) // @Sink(at18)
}

func generateData18() *S {
	return &S{next: &S{v: source1()}, v: "ok"} // @Source(at18)
}

func testAT19() {
	s := generateData19()
	s2 := any(s.v)
	sink2(s2.(string)) // @Sink(at19)
}

func generateData19() *S {
	return &S{next: &S{v: source1()}, v: "ok"} // @Source(at19)
}

func testAT20() {
	println("AT20")
	v := V{&U{"content"}}
	x := [10]*U{}
	x[0] = &U{"fine"}
	x[1] = v.data
	x[2] = &U{"fine"}
	AT20_populate(&v)
	AT20_consume(x)
}

func AT20_consume(c [10]*U) {
	for _, x := range c {
		AT20_callSink(x)
	}
}

func AT20_callSink(x *U) {
	sink1(x.content) // @Sink(at20)
}

func AT20_populate(v *V) {
	s := source1() // @Source(at20)
	new_u := &U{s}
	AT20_assign(new_u.content, v.data)
}

func AT20_assign(val string, data *U) {
	data.content = val
}

func testAT21() {
	s := new(S)
	s.next = new(S)
	u := s.next
	s.next.v = source1() //@Source(at21)
	sink1(u.v)           //@Sink(at21)
}

func testAT22() {
	a := make([]*V, 10)
	s := &S{}
	for i := 0; i < 10; i++ {
		a[i] = &V{&U{s.v}} // value copied
	}
	s.v = source1()
	AT22_callSink(a[3].data)
}

func AT22_callSink(x *U) {
	sink1(x.content) // @Sink(at22)
}

func testAT23() {
	a := make([]*X, 10)
	s := &S{v: "x"}
	for i := 0; i < 10; i++ {
		a[i] = &X{&Y{s}}
	}
	b := make([]*V, 10)
	for i := 0; i < 10; i++ {
		b[i] = &V{&U{s.v}} // value copied
	}
	s.v = source1() // @Source(at23)
	AT23_callSink(b[3].data, a[3].data.content)
}

func AT23_callSink(u *U, x *S) {
	sink1(u.content) // no tainted data reaching here
	sink1(x.v)       // @Sink(at23)
}
