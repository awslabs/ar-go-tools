package main

func foo() {
	panic("whatnot")
}

func bar() {
	panic("whatnot")
}

func main() {
	go foo()
	go bar()
}
