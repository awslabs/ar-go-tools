package main

import "fmt"

func sinkFunction(s string) {
	fmt.Printf("That's a sink receiving %s!\n", s)
}

func notSinkFunction(s string) {
	fmt.Printf("That's not a sink with %s.\n", s)
}

func main() {
	sinkFunction("tainted data") // want "found a sink"
	notSinkFunction("tainted data")
}
