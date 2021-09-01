package main

func notReachable() {
}

func reachable() {
}

var f func() = reachable

func main() {
        f() // calls 'reachable'
}
