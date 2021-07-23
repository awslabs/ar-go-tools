package main

import "fmt"

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered", r)
		}
	}()

	done := make(chan bool)

	go func() {
		// separate go-routine, not caught by the above
		panic("whatnot")
	}()

	// wait till done
	<-done
}
