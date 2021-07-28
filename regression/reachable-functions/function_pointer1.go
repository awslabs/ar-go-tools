package main

func notReachable() {
}

func reachable() {
}

func main() {
        var f func()

        if f == nil {
                f = reachable
        }

        f() // calls 'reachable'
}
