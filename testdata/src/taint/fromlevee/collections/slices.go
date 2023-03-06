package collections

import (
	"fromlevee/core"
)

func TestSlices(s core.SourceT) {
	slice := []core.SourceT{s}
	core.Sink(slice)                      // @Sink(sl1)
	core.Sink([]core.SourceT{s})          // @Sink(sl1)
	core.Sink([]interface{}{s})           // @Sink(sl1)
	core.Sink([]interface{}{0, "", s})    // @Sink(sl1)
	core.Sink([]interface{}{0, "", s}...) // @Sink(sl1)
}

func TestRangeOverSlice() {
	sources := []core.SourceT{core.Source2()} // @Source(sl2)
	for i, s := range sources {
		core.Sink(s) // @Sink(sl2)
		core.Sink(i)
	}
}

func TestRangeOverInterfaceSlice() {
	for i, s := range []interface{}{core.Source2()} { // @Source(sl3)
		core.Sink(s) // @Sink(sl3)
		core.Sink(i)
	}
}

func TestSliceBoundariesAreNotTainted(lo, hi, max int) {
	sources := [4]core.SourceT{core.Source2(), core.Source2()} // @Source(sl4)
	slice := sources[lo:hi:max]
	core.Sink(lo)
	core.Sink(hi)
	core.Sink(max)
	_ = slice
}

func TestSlicedArrayIsTainted() {
	innocs := [1]interface{}{nil}
	slice := innocs[:]
	slice[0] = core.Source2() // @Source(sl5)
	core.Sink(innocs)         // @Sink(sl5)
	_ = slice
}

func TestAllSlices() {
	TestSlices(core.Source2()) // @Source(sl1)
	TestRangeOverSlice()
	TestRangeOverInterfaceSlice()
	TestSliceBoundariesAreNotTainted(0, 1, 2)
	TestSlicedArrayIsTainted()
}
