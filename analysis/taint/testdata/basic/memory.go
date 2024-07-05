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
	"math/rand"
	"strconv"
)

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
	testAT24()
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
	At2Populate(&v)
	At2Consume(x)
}

func At2Consume(content *string) {
	sink1(*content) // @Sink(at2)
}

func At2Populate(v *V) {
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
	At3Handle(b)
}

func At3Handle(s *S) {
	sink1(s.next.v) // @Sink(at3)
}

func testAT4() {
	a := &S{}
	b := &S{a, "ok"}
	At4Handle(b)
	a.v = source1() // tainted after AT4_handle is called.
}

func At4Handle(s *S) {
	sink1(s.next.v)
}

func testAT5() {
	a := &S{}
	b := map[string]*S{"ok": a}
	a.v = source1() // @Source(at5) --> whole map is tainted here
	At5Handle(b)
}

func At5Handle(s map[string]*S) {
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
	At6Populate(&v)
	At6Consume(x)
}

func At6Consume(content map[string]string) {
	for _, val := range content {
		sink1(val) // no taint flows here
	}
}

func At6Populate(v *V) {
	v.data.content = source1()
}

func testAT7() {
	key := "ok"
	sourceMap := map[*string]string{&key: source1()}
	At7Consume(&key, sourceMap)
}

func At7Consume(key *string, sources map[*string]string) {
	delete(sources, key)
	sink1(*key) // The key is not tainted
}

func testAT8() {
	println("AT8")
	v := V{&U{"content"}}
	x := map[string]*U{"ok1": &U{"content2"}}
	x["ok"] = v.data
	At8Populate(&v)
	At8Consume(x)
}

func At8Consume(content map[string]*U) {
	for _, val := range content {
		sink1(val.content) // @Sink(at8)
	}
}

func At8Populate(v *V) {
	v.data.content = source1() // @Source(at8)
}

func testAT9() {
	println("AT9")
	v := V{&U{"content"}}
	x := []*U{&U{"content2"}}
	x[0] = v.data
	At9Populate(&v)
	At9Consume(x)
}

func At9Consume(content []*U) {
	for _, val := range content {
		sink1(val.content) // @Sink(at9)
	}
}

func At9Populate(v *V) {
	v.data.content = source1() // @Source(at9)
}

func testAT10() {
	a := &S{}
	b := []*S{a}
	a.v = source1() // @Source(at10) --> whole slice is tainted here
	At10Handle(b)
}

func At10Handle(s []*S) {
	for _, val := range s {
		sink1(val.v) // @Sink(at10)
	}
}

func testAT11() {
	println("AT11")
	a := &S{}
	b := []S{*a} // value is stored in slice, not pointer
	a.v = source1()
	At11Handle(b)
}

func At11Handle(s []S) {
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
	At12Handle(c)
}

func At12Handle(s []*S) {
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
	At13Handle(c)
}

func At13Handle(s []*S) {
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
	At14Populate(&v)
	At14Consume(x)
}

func At14Consume(content chan string) {
	sink1(<-content)
}

func At14Populate(v *V) {
	v.data.content = source1()
}

func testAT15() {
	println("AT15")
	v := V{&U{"content"}}
	x := make(chan *U, 10)
	x <- &U{"fine"}
	x <- v.data // pointer to U into channel
	At15Populate(&v)
	At15Consume(x)
}

func At15Consume(c chan *U) {
	sink1((<-c).content) // @Sink(at15)
	sink1((<-c).content) // @Sink(at15)
}

func At15Populate(v *V) {
	v.data.content = source1() // @Source(at15)
}

func testAT16() {
	println("AT16")
	a := &S{}
	b := make(chan *S, 10)
	b <- a
	a.v = source1() // @Source(at16)
	At16Handle(b)
}

func At16Handle(s chan *S) {
	sink1((<-s).v) // @Sink(at16)
}

func testAT17() {
	println("AT17")
	a := &S{next: &S{}}
	b := make(chan *S, 10)
	b <- a
	a.v = "ok"
	a.next.v = source1() // @Source(at17)
	At17Handle(b)
}

func At17Handle(s chan *S) {
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
	At20Populate(&v)
	At20Consume(x)
}

func At20Consume(c [10]*U) {
	for _, x := range c {
		At20Callsink(x)
	}
}

func At20Callsink(x *U) {
	sink1(x.content) // @Sink(at20)
}

func At20Populate(v *V) {
	s := source1() // @Source(at20)
	newU := &U{s}
	At20Assign(newU.content, v.data)
}

func At20Assign(val string, data *U) {
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
	At22Callsink(a[3].data)
}

func At22Callsink(x *U) {
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
	At23Callsink(b[3].data, a[3].data.content)
}

func At23Callsink(u *U, x *S) {
	sink1(u.content) // no tainted data reaching here
	sink1(x.v)       // @Sink(at23)
}

func testAT24() {
	a := make([]*X, 20)
	for i := 0; i < 20; i++ {
		a[i] = &X{data: &Y{&S{v: strconv.Itoa(i * rand.Int())}}}
		sink1(a[i].data.content.v)
	}
	y := at24takeAlias(a)   // grab an alias of a struct in the array
	at24populate(y.content) // put tainted data in its content
	at24consume(a)          // consume the array by calling the sink on it
}

func at24populate(s *S) {
	if s != nil {
		s.v = source1() // @Source(at24)
	}
}

func at24takeAlias(a []*X) *Y {
	for i := range a {
		if i > rand.Int() {
			return a[i].data
		}
	}
	return nil
}

func at24consume(a []*X) {
	for _, elt := range a {
		if elt.data != nil && elt.data.content != nil {
			sink1(elt.data.content.v) //@Sink(at24)
		}
	}
}
