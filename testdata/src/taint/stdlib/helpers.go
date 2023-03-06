package main

import (
	"fmt"
	"math/rand"
	"strconv"
)

type T struct {
	Data  string
	Other string
}

type R string

func genStr() string {
	return strconv.Itoa(rand.Int()) + "1234"
}

func genT() T {
	return T{
		Data:  genStr(),
		Other: genStr() + "ok",
	}
}

func source1() T {
	return T{
		Data:  strconv.Itoa(rand.Int()) + "tainted",
		Other: "ok",
	}
}

func source2() R {
	return R(strconv.Itoa(rand.Int()) + "tainted")
}

func sink2(_ ...any) {}

func sink1(s string) {
	fmt.Printf("Sink: %s\n", s)
}
