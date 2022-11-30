package main

import "fmt"

func source2(x int) string {
	s := ""
	for i := 0; i < x; i++ {
		s += "a"
	}
	return s
}

func producer(x chan string) {
	x <- source2(10)
}

func producerCaller(b chan string) {
	b <- "ok"
	producer(b)
}

func consumer(b chan string) {
	sink2(<-b) // want "reached by tainting call on line 14"
}

func test1() {
	b := make(chan string, 3)
	producerCaller(b)
	fmt.Printf("Example: %s, %s", <-b, "ok")
	consumer(b)
}

func sink2(s string) {
	fmt.Printf("Log: %s", s)
}
