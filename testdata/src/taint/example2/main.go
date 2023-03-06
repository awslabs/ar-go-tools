package main

import (
	"fmt"
	"strings"
)

func extract(name string) string {
	if !strings.HasSuffix(name, ").Error") {
		return ""
	}
	name = name[:len(name)-7]
	if !strings.HasPrefix(name, "(") {
		return ""
	}
	name = name[1:]
	if strings.HasPrefix(name, "*") {
		name = name[1:]
	}
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[:i]
}

func source1() string {
	return "tainted"
}

func sink1(x any) {
	fmt.Println(x)
}

func rec(x string) string {
	switch x {
	case "":
		return rec("b")
	case "a":
		return rec(x + "b")
	case "b":
		return rec("a")
	case "ab":
		return x
	default:
		return rec(x[1:])
	}
}

func main() {
	x := fmt.Sprintf("%s", rec(rec(source1()))) // @Source(source1)
	y := extract(x)
	if len(y) > 2 {
		return
	}
	z := extract(extract(y))
	sink1(z) // @Sink(source1)
}
