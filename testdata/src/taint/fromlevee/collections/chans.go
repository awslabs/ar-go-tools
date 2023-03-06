package collections

import (
	"fromlevee/core"
)

func TestSourceReceivedFromChannelIsTainted(sources <-chan core.SourceT) {
	s := <-sources
	core.Sink(s) // @Sink(c)
}

func TestChannelIsTaintedWhenSourceIsPlacedOnIt(sources chan<- core.SourceT) {
	sources <- core.Source2() //@Source(c2)
	core.Sink(sources)        // @Sink(c2)
}

func TestValueObtainedFromTaintedChannelIsTainted(c chan interface{}) {
	c <- core.Source2() // @Source(c3)
	s := <-c
	core.Sink(s) // @Sink(c3)
}

func TestChannelIsNoLongerTaintedWhenNilledOut(sources chan core.SourceT) {
	sources <- core.Source2()
	sources = nil
	core.Sink(sources) // -- not tainted! flow sensitivity from ssa
}

func TestRangeOverChan(sources chan core.SourceT) {
	for s := range sources {
		core.Sink(s) // @Sink(c)
	}
}

func TestAllChan() {
	c := make(chan core.SourceT, 10)
	c <- core.Source2() // @Source(c)
	TestSourceReceivedFromChannelIsTainted(c)
	TestRangeOverChan(c)

	c2 := make(chan core.SourceT, 10)
	TestChannelIsTaintedWhenSourceIsPlacedOnIt(c2)

	c3 := make(chan interface{}, 10)
	TestValueObtainedFromTaintedChannelIsTainted(c3)

	c4 := make(chan core.SourceT, 10)
	TestChannelIsNoLongerTaintedWhenNilledOut(c4)

}
