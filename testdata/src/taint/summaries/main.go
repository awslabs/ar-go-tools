package main

import "fmt"

type A struct {
	x string
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

func main() {
	s := fmt.Sprintf("bad-%s", "data")
	s2 := "example2"
	obj := A{x: "ex"}
	Foo(s, &s2, obj)
	c := make(chan string, 10)
	c <- s2
	go ChannelProducer(c)
	go ChannelConsumer(c)
}
