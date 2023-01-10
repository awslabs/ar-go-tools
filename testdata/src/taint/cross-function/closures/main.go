package main

import "fmt"

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
	rparen := source()
	parenthesize := func(a string) string { return wrap(a, lparen, rparen) }
	x := "ok"
	y := parenthesize(x)
	sink(y) // TODO: WIP, tainted data flows here!
}

//// In this example, a variable captured by the closure is modified after the closure is created, and contains
//// tainted data. Calling the closure will result in tainted data.
//func example2() {
//	lparen := "("
//	rparen := ")"
//	parenthesize := func(a string) string { return wrap(a, lparen, rparen) }
//	lparen = source() // @ Source(lparen)
//	y := parenthesize("good")
//	sink(y) // @ Sink(lparen)
//}
//
//// In this example, a variable captured by the closure is tainted after the closure is created, and the closure
//// is returned. Any value returned by the closure will be tainted.
//func example3prep() func(string) string {
//	lparen := "("
//	rparen := ")"
//	parenthesize := func(a string) string { return wrap(a, lparen, rparen) }
//	rparen = source() // @ Source(3)
//	return parenthesize
//}
//
//func example3() {
//	closure := example3prep()
//	x := closure("a")
//	sink(x) // @ Sink(3)
//}
//
//// In this example, the closure returned by example4pre captures the argument of the function. If the argument
//// of example4pre is tainted, then the returned closure always returns tainted data.
//func example4pre(x string) func(string) string {
//	parenthesize := func(a string) string { return wrap(a, x, ")") }
//	return parenthesize
//}
//
//func example4() {
//	pre := source() // @ Source(4)
//	closure := example4pre(pre)
//	sink(closure("A")) // @ Sink(4)
//}
//
//func example4bis() {
//	pre := "("
//	closure := example4pre(pre)
//	pre = source()
//	sink(closure("A")) // this is ok, the argument to example4pre was passed by value
//}
//
//// In this example, the closure returned by example5pre captures the argument of the function. If the argument
//// of example4pre is tainted, then the returned closure always returns tainted data.
//// The argument is passed by reference.
//func example5pre(x *string) func(string) string {
//	parenthesize := func(a string) string { return wrap(a, *x, ")") }
//	return parenthesize
//}
//
//func example5() {
//	pre := "("
//	closure := example5pre(&pre)
//	pre = source()     // @ Source(5)
//	sink(closure("A")) // @ Sink(5) the argument pre was passed "by reference"
//}

func main() {
	example1()
	example1bis()
	//example2()
	//example3()
	//example4()
	//example4bis()
	//example5()
}
