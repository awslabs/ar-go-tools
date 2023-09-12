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

func TestCopy() {
	a := []T{source1()} // @Source(ex1)
	b := make([]T, 2)
	n := copy(b, a)
	sink(n)
	sink(b[0]) // @Sink(ex1)
}

func TestAppend() {
	a := []T{source1()} // @Source(ex2)
	b := append(a, T{})
	sink(b) // @Sink(ex2)
}

func TestAppend2() {
	a := []T{{}, {}}
	b := append(a, source1()) // @Source(ex3)
	sink(a)                   // @Sink(ex3)
	sink(b)                   // @Sink(ex3)
}

func TestCopy2() {
	x := source1() // @Source(copy2)
	a := []*T{&x}
	var b []*T
	copy(b, a)
	sink(b[0]) // @Sink(copy2)
}

func TestNew() {
	a := new(T)
	b := source1() // @Source(new1)
	a.Data = b.Data
	sink(a) // @Sink(new1)
}

func TestLen() {
	x := source1() // @Source(len)
	a := []*T{&x, &x}
	sink(len(a)) // @Sink(len)
}

func TestPrintln() {
	x := source1()  // @Source(println)
	println(x.Data) // nothing happens with println
	sink(x)         // @Sink(println)
}

func TestPrint() {
	x := source1() // @Source(print)
	print(x.Data)  // nothing happens with print
	sink(x)        // @Sink(print)
}

func TestClose() {
	c := make(chan T, 10)
	c <- source1() // @Source(close)
	s := <-c
	close(c) // nothing happens
	sink(s)  // @Sink(close)
}

func TestDelete() {
	a := make(map[string]T, 10)
	a["key1"] = source1() // @Source(delete1)
	a["key2"] = source1() //@Source(delete2)
	delete(a, "key1")     // delete doesn't erase taint.
	sink(a["key2"])       // @Sink(delete1, delete2)
}

func TestComplex() {
	f1 := source3() // @Source(complex1)
	f2 := source3() // @Source(complex2)
	c := complex(f1, f2)
	sink(c) // @Sink(complex1, complex2)
}

func TestCap() {
	var a []T
	a = append(a, source1())
	a = append(a, source1())
	c1 := cap(a)
	sink(c1)
	ch := make(chan T, 10)
	ch <- source1()
	c2 := cap(ch)
	sink(c2)
}

func TestImag() {
	f1 := source3() // @Source(imag1)
	f2 := source3() // @Source(imag2)
	c := complex(f1, f2)
	i := imag(c)
	sink(i) // @Sink(imag1, imag2)
}

func TestImag2() {
	f1 := float32(1.0)
	f2 := source3() // @Source(imag21)
	c := complex(f1, f2)
	i := imag(c)
	sink(i) // @Sink(imag21)
}

func TestReal() {
	f1 := source3() // @Source(real1)
	f2 := source3() // @Source(real2)
	c := complex(f1, f2)
	i := real(c)
	sink(i) // @Sink(real1, real2)
}

func TestReal2() {
	f1 := source3() // @Source(real21)
	f2 := float32(1)
	c := complex(f1, f2)
	i := real(c)
	sink(i) // @Sink(real21)
}

func main() {
	TestCopy()
	TestCopy2()
	TestAppend()
	TestAppend2()
	TestNew()
	TestLen()
	TestPrintln()
	TestPrint()
	TestClose()
	TestDelete()
	TestComplex()
	TestCap()
	TestImag()
	TestImag2()
	TestReal()
	TestReal2()
}
