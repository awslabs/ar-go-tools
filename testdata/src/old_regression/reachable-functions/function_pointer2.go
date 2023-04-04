package main

func notReachable() {
}

func reachable() {
}

var f = reachable

func main() {
	f() // calls 'reachable'
}
