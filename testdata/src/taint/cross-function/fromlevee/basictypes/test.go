package basic

import (
	"fromlevee/core"
)

func BooleansDontPropagateTaint(s *string) {
	is := isSourcey(s)
	core.Sink(is)
}

func isSourcey(_ interface{}) bool {
	// not taking any chances
	return true
}

func IntegersDontPropagateTaint(sources []string) {
	core.Sink(len(sources)) // @Sink(basic) - TODO: levee doesn't propagate taint through integers - should we?
}

func TestAll() {
	s := core.Source() // @Source(basic)
	BooleansDontPropagateTaint(&s)
	IntegersDontPropagateTaint([]string{s})
}
