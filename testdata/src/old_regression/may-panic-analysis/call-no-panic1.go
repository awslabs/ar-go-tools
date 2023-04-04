package main

func someFunc() {
}

func panickyFunc() {
	panic("ouch!")
}

func otherFunc() {
}

func main() {
	someFunc()
	otherFunc()
}
