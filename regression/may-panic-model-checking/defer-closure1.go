package main

import "fmt"

func main() {
	var s = "hello"

	// 's' will be captured
	defer func() {
		if msg := recover(); msg != nil {
			// recovered
			fmt.Println(s)
		}
	}()

	panic("whatnot")
}
