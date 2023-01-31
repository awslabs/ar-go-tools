package closures

import (
	"fromlevee/core"
)

func TesCapturedSourceReachesSinkInClosure() func() {
	s0 := core.Source() // @Source(clo1)
	return func() {
		core.Sink("%v", s0) // @Sink(clo1)
	}
}

func TestSourceReachesSinkInClosure() func() {
	return func() {
		s0 := core.Source() // @Source(clo2)
		core.Sink("%v", s0) // @Sink(clo2)
	}
}

func TestAll() {
	TesCapturedSourceReachesSinkInClosure()()
	TestSourceReachesSinkInClosure()()
}
