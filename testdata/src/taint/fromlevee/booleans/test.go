// This set of tests is borrowed from go-flow-levee

package booleans

import (
	"fromlevee/core"
)

func hasSecret(s core.Container) bool {
	return s.Data != ""
}

func TestDoNotTraverseToBoolean() {
	ok := hasSecret(core.Container{Data: core.Source()}) // @Source(bool1)
	core.Sink(ok)                                        // @Sink(bool1) - TODO: levee does not propagate taint with booleans - should we?
}
