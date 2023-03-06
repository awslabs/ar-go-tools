package main

import "fmt"

// This is a simple example that doesn't do much, but also does not use any goroutines
func testSelect1() {
	x := R("ok")
	var y R
	c := make(chan R, 10)
	quit := make(chan int)

	for {
		select {
		case c <- x:
			x = source2() // @Source(test1)
		case y = <-c:
			sink(y) // @Sink(test1)
		case <-quit:
			fmt.Println("quit")
			return
		}
	}

}

func main() {
	testSelect1()
}
