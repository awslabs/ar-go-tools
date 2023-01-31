package core

import (
	"fmt"
	"math/rand"
	"strconv"
)

type SourceT string

type Container struct {
	Data string
}

func Source1() string {
	return strconv.Itoa(rand.Int()) + "tainted"
}

func Source() string {
	return strconv.Itoa(rand.Int()) + "tainted"
}

func Source2() SourceT {
	return SourceT(strconv.Itoa(rand.Int()) + "tainted")
}

func Source3() Container {
	return Container{Data: "tainted" + strconv.Itoa(rand.Int())}
}

func Sink(x ...any) {
	fmt.Println(x)
}

func Innocuous() string {
	return "ok"
}
