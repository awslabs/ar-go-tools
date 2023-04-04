package main

func notReachable() {
}

func alsoNotReachable() {
	notReachable()
}

func reachable() {
}

func main() {
	reachable()
}
