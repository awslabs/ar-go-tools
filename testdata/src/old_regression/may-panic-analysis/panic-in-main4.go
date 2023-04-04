package main

import "flag"
import "fmt"

func main() {

	flag.Parse()

	if len(flag.Args()) == 0 {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered", r)
			}
		}()
	}

	panic("whatnot")
}
