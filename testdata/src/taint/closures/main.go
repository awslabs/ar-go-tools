package main

import (
	"fmt"
	random "math/rand"
	"strconv"
)

func wrap(a string, before string, after string) string {
	return fmt.Sprintf("%s%s%s", before, a, after)
}

// In this example, the argument to the closure is the source
func example1() {
	lparen := "("
	rparen := ")"
	parenthesize := func(a string) string { return wrap(a, lparen, rparen) }
	x := source() // @Source(x)
	y := parenthesize(x)
	sink(y) // @Sink(x)
}

// In this example, the closure binds tainted data
func example1bis() {
	lparen := "("
	rparen := source() // @Source(example1bis)
	parenthesize := func(a string) string { return wrap(a, lparen, rparen) }
	x := "ok"
	y := parenthesize(x)
	sink(y) // @Sink(example1bis)
}

// In this example, a variable captured by the closure is modified after the closure is created, and contains
// tainted data. Calling the closure will result in tainted data.
func example2() {
	lparen := "("
	rparen := ")"
	parenthesize := func(a string) string { return wrap(a, lparen, rparen) }
	lparen = source() // @Source(example2)
	y := parenthesize("good")
	sink(y) // @Sink(example2)
}

// In this example, a variable captured by the closure is tainted after the closure is created, and the closure
// is returned. Any value returned by the closure will be tainted.
func example3prep() func(string) string {
	lparen := "("
	rparen := ")"
	parenthesize := func(a string) string { return wrap(a, lparen, rparen) }
	rparen = source() // @Source(example3)
	return parenthesize
}

func example3() {
	closure := example3prep()
	x := closure("a")
	sink(x) // @Sink(example3)
}

// In this example, the closure returned by example4pre captures the argument of the function. If the argument
// of example4pre is tainted, then the returned closure always returns tainted data.
func example4pre(x string) func(string) string {
	parenthesize := func(a string) string { return wrap(a, x, ")") }
	return parenthesize
}

func example4() {
	pre := source() // @Source(example4)
	closure := example4pre(pre)
	sink(closure("A")) // @Sink(example4)
}

func example4bis() {
	pre := "("
	closure := example4pre(pre)
	pre = source()
	sink(closure("A")) // This is not tainted
}

// In this example, the closure returned by example5pre captures the argument of the function. If the argument
// of example5pre is tainted, then the returned closure always returns tainted data.
// The argument is passed by reference.

func example5pre(x *string) func(string) string {
	parenthesize := func(a string) string { return wrap(a, *x, ")") }
	return parenthesize
}

func example5() {
	pre := "("
	closure := example5pre(&pre)
	pre = source()     // @Source(example5)
	sink(closure("A")) // @Sink(example5) the argument pre was passed "by reference"
}

// example6 creates nested closures. Tainted data is produced after the closure is created.

func example6() {
	x := fmt.Sprintf("%dx", random.Int())
	fx := func() string {
		fin := func() string { return x }
		return fin()
	}
	x = source() // @Source(example6)
	y := fx()
	sink(y) // @Sink(example6)
}

// example7 creates nested closures. Tainted data is produced inside the closure

func example7() {
	x := fmt.Sprintf("%dx", random.Int())
	fx := func() string {
		x = source() // @Source(example7)
		fin := func() string { return x }
		return fin()
	}
	y := fx()
	sink(y) // @Sink(example7)
}

func example7bis() {
	x := fmt.Sprintf("%dx", random.Int())
	fx := func() string {
		fin := func() string { return x }
		x = source() // @Source(example7bis)
		return fin()
	}
	y := fx()
	sink(y) // @Sink(example7bis)
}

type Example8Struct struct {
	SourceField func() string
	OtherData   func() string
}

func passing(s string, s2 string) string {
	return s2 + s
}

func example8() {
	s := Example8Struct{
		SourceField: func() string { return source() }, // @Source(example8)
		OtherData:   func() string { return "not tainted" },
	}
	s2 := "ok"
	s3 := passing(s.SourceField(), s2)
	s4 := fmt.Sprintf("%s", s3)
	sink(s4) // @Sink(example8)
}

// This is a variation of example 5 with more degrees of nesting

func example9pre(x *string) func(string) string {
	parenthesizeN := func(a string, b int) string {
		s := *x
		for i := 0; i < b; i++ {
			s = wrap(a, s, ")")
		}
		return s
	}
	return func(x string) string { return parenthesizeN(x, 0) }
}

func example9() {
	pre := "("
	closure := example9pre(&pre)
	pre = source()     // @Source(example9)
	sink(closure("A")) // @Sink(example9) the argument pre was passed "by reference"
	ok := "("
	closure2 := example9pre(&ok)
	sink(closure2("B")) // @Sink(example9) TODO: overapproximation
}

// A variation of example9 with an additional function calling the sink
func example10pre(x *string) func(string) string {
	parenthesizeN := func(a string, b int) string {
		s := *x
		for i := 0; i < b; i++ {
			s = wrap(a, s, ")")
		}
		return s
	}
	return func(x string) string { return parenthesizeN(x, 0) }
}

func callSink(f func(string) string, arg string) {
	x := f(arg)
	sink(x) // @Sink(example10)
}

func example10() {
	pre := "("
	closure := example10pre(&pre)
	pre = source() // @Source(example10)
	callSink(closure, "A")
}

// example11 is a case where a closure is assigned to a struct's field, and the closure is called later

type Ex11 struct {
	Count  int
	Lambda func(int, string) string
}

func (e Ex11) Run(s string) string {
	e.Count += 1
	return e.Lambda(e.Count, s)
}

func example11() {
	e := Ex11{
		Count: 0,
		Lambda: func(i int, s string) string {
			return source() + strconv.Itoa(i) + s // @Source(ex11)
		},
	}
	sink(e.Run("ok")) // @Sink(ex11)
}

// example12 is variation of example11

func NewEx11() *Ex11 {
	e := &Ex11{
		Count: 0,
		Lambda: func(i int, s string) string {
			return strconv.Itoa(i) + s
		},
	}
	return e
}

func example12() {
	e := NewEx11()
	sink(e.Run("ok")) // @Sink(ex11) TODO: false positive here because Run is called and was tainted in ex11
}

// example13

type Ex13 struct {
	Count  int
	Lambda func(int, string) string
}

func (e Ex13) Run(s string) string {
	e.Count += 1
	return e.Lambda(e.Count, s)
}

func NewEx13() *Ex13 {
	e := &Ex13{
		Count: 0,
		Lambda: func(i int, s string) string {
			return strconv.Itoa(i) + s + source() // @Source(ex13)
		},
	}
	return e
}

func callSinkS(run func(string) string, s string) {
	sink(run(s)) // @Sink(ex13)
}

func example13() {
	e := NewEx13()
	f := e.Run
	callSinkS(f, "ok")
}

// example14

type Ex14 struct {
	Count  int
	Lambda func(int, string) string
}

func (e Ex14) Run(s string, i int) string {
	e.Count += i
	return e.Lambda(e.Count, s)
}

func NewEx14() *Ex14 {
	data := source() // @Source(ex14)
	e := &Ex14{
		Count: 0,
		Lambda: func(i int, s string) string {
			return strconv.Itoa(i) + s + data
		},
	}
	return e
}

func callSink14(run func(string) string, s string) {
	sink(run(s)) // @Sink(ex14)
}

func example14() {
	e := NewEx14()
	f := e.Run
	callSink14(func(s string) string { return f(s, 1) }, "ok")
}

func main() {
	example1()
	example1bis()
	example2()
	example3()
	example4()
	example4bis()
	example5()
	example6()
	example7()
	example7bis()
	example8()
	example9()
	example10()
	example11()
	example12()
	example13()
	example14()
}
