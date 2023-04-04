package main

import "fmt"

func main() {
	// this fails, since 'defer' is executed in the reverse order
	defer panic("whatnot")

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered", r)
		}
	}()
}
