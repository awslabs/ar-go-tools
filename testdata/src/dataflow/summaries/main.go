package main

import "fmt"

var global string

type A struct {
	x string
}

type B struct {
	Source string
}

func (a A) f(i string) string {
	return a.x + i
}

func Source() string {
	return "tainted"
}

func Sink(s string) {
	fmt.Println(s)
}

func Bar(x string) int {
	fmt.Println(x)
	return len(x)
}

func ChannelConsumer(c chan string) int {
	x := <-c
	Sink(x)
	return Bar(x)
}

func ChannelProducer(c chan string) {
	c <- Source()
}

func Foo(s string, s2 *string, obj A) int {
	a := make([]string, 10)
	a[0] = s
	for i := 1; i < 10; i++ {
		a[i] = a[i-1]
	}
	*s2 = obj.f(a[9])
	l := Bar(*s2)
	return l
}

func FooBar(x string) {
	s := B{Source: x}
	s2 := "ok"
	s3 := Foo(s.Source, &s2, A{})
	s4 := fmt.Sprintf("%s", s3)
	Sink(s4)
}

func Baz(x string) {
	s := B{Source: x}
	global = s.Source
	s1 := fmt.Sprintf("%s", global)
	Sink(s1)

	ok := "ok" // bound variable
	closure := func(s string) string {
		Sink(s1)
		s4 := fmt.Sprintf("%s", s)
		Sink(s4)
		return s + ok
	}
	s5 := closure(ok)
	ok = s.Source
	Sink(s5)
}

func main() {
	s := fmt.Sprintf("bad-%s", "data")
	s2 := "example2"
	obj := A{x: "ex"}
	Foo(s, &s2, obj)
	FooBar("x")
	c := make(chan string, 10)
	c <- s2
	go ChannelProducer(c)
	go ChannelConsumer(c)
	x := Source()
	Baz(x)
}
