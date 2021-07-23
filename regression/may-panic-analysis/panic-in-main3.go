package main

import "flag"

func main() {

	flag.Parse()

	if len(flag.Args()) == 0 {
		panic("whatnot")
	}
}
