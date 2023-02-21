package main

import (
	"fmt"
	"os"
)

func main() {
	var a *string
	var err error
	err = nil
	a = nil
	x := 1
	if x > 0 {
		y := 1
		fmt.Printf("%d, %d, %v\n", y, a, err)
	}
}

// test2 this is some documentations
func test2() {
	f, err := os.Open("main.go")
	// This comment is supposed to appear before if and stay here
	if err != nil {
		return
	} else {
		f.WriteString("example")
		fmt.Printf("Wrote string\n")
		if len(f.Name()) > 2 {
			f.WriteString("another line")
		}

		// This comment should stay here, even though the statement below will change
		f.WriteString("another line")
	}
}
