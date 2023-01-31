package binop

import (
	"fmt"

	"fromlevee/core"
)

func TestConcatenatingTaintedAndNonTaintedStrings(prefix string) {
	s := core.Container{Data: core.Source()} // @Source(bin1)
	message := fmt.Sprintf("source: %v", s)
	fullMessage := prefix + message
	core.Sink(prefix)
	core.Sink(message)     // @Sink(bin1)
	core.Sink(fullMessage) // @Sink(bin1)
}

func TestAll() {
	TestConcatenatingTaintedAndNonTaintedStrings("ok - ")
}
