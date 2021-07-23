package main

import "fmt"

func main() {
	panic("whatnot")

	// too late
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered", r)
		}
	}()
}
