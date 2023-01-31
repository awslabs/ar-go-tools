// This set of tests is borrowed from go-flow-levee

package store

import (
	"fromlevee/core"
)

func TestStoringToTaintedAddrDoesNotTaintStoredValue() {
	myChan := make(chan string)
	s := core.Container{Data: core.Source()}
	recv := <-myChan
	s.Data = recv
	core.Sink(recv)
	core.Sink(myChan)
}
