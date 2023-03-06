// This set of tests is borrowed from go-flow-levee

package callorder

import (
	"fmt"
	"fromlevee/core"
	"io"
	"os"
)

func TestTaintedColocatedArgumentDoesNotReachSinkThatPrecedesColocation(w io.Writer) {
	src := core.Source()
	if true {
		core.Sink(w)
	}
	fmt.Fprint(w, src)
}

func TestTaintedColocatedArgumentReachesSinkThatFollowsColocation(w io.Writer) {
	src := core.Source() // @Source(co1)
	if _, err := fmt.Fprint(w, src); err != nil {
		core.Sink(w) // @Sink(co1)
	}
}

func TestAvoidingIncorrectPropagationFromColocationDoesNotPreventCorrectReport(w io.Writer) {
	src := core.Source() // @Source(co2)
	_, err := fmt.Fprint(w, src)
	if err != nil {
		core.Sink(w) // @Sink(co2)
	}

	if true {
		fmt.Fprint(w, src)
	}
}

func TestAllColocation() {
	TestTaintedColocatedArgumentReachesSinkThatFollowsColocation(os.Stdout)
	TestTaintedColocatedArgumentDoesNotReachSinkThatPrecedesColocation(os.Stdout)
	TestAvoidingIncorrectPropagationFromColocationDoesNotPreventCorrectReport(os.Stdout)
}
