package main

import "fmt"

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered", r)
		}
	}()

	// this works, since 'defer' is executed in the reverse order
	defer panic("whatnot")
}
