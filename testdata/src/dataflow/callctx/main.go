package main

import "fmt"

func main() {
	f()
	g("ok")
}

func f() {
	g("ok")
}

func g(s string) {
	fmt.Println("Message:", s)
}
