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
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered", r)
				done <- true
			}
		}()

		panic("whatnot")
	}()

	// wait till done
	<-done
}
