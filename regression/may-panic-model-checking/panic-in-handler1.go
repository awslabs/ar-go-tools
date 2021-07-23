package main

import "fmt"

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered", r)
			panic("second panic") // panic again
		}
	}()

	panic("first panic")
}
