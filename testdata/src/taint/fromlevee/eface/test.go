// This set of tests is borrowed from go-flow-levee

package eface

import (
	"fromlevee/core"
)

func TestEfaceSource() {
	s := core.Source() // @Source(ef1)
	var ss interface{} = s
	core.Sink(ss) // @Sink(ef1)
}

func TestEfaceSourcePointer() {
	s := core.Source() // @Source(ef2)
	var ss interface{} = s
	core.Sink(ss) // @Sink(ef2)
}

func TestAll() {
	TestEfaceSource()
	TestEfaceSourcePointer()
}
