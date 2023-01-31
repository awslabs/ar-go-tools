package main

func sink(a ...string) {
	for _, x := range a {
		println(x)
	}
}

func source() string {
	return "-tainted-"
}
