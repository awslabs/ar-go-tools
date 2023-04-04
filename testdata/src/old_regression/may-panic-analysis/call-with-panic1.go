package main

func someFunc() {
}

func panickyFunc() {
	panic("ouch!")
}

func otherFunc() {
	panickyFunc()
}

func main() {
	someFunc()
	otherFunc()
}
