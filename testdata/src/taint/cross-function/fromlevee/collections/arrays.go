package collections

import (
	"fromlevee/core"
)

func TestArrayLiteralContainingSourceIsTainted(s core.SourceT) {
	tainted := [1]core.SourceT{s}
	core.Sink(tainted) // @Sink(ar2)
}

func TestArrayIsTaintedWhenSourceIsInserted(s core.SourceT) {
	arr := [2]interface{}{nil, nil}
	arr[0] = s
	core.Sink(arr) // @Sink(ar1)
}

func TestValueObtainedFromTaintedArrayIsTainted(s core.SourceT) {
	arr := [2]interface{}{nil, nil}
	arr[0] = s
	core.Sink(arr[1]) // @Sink(ar3)
}

func TestArrayRemainsTaintedWhenSourceIsOverwritten(s core.SourceT) {
	arr := [2]interface{}{s, nil}
	arr[0] = nil
	core.Sink(arr) // @Sink(ar4)
}

func TestRangeOverArray() {
	sources := [1]core.Container{{Data: core.Source1()}} // @Source(ar5)
	for i, s := range sources {
		core.Sink(s) // @Sink(ar5)
		core.Sink(i)
	}
}

func TestAllArrays() {
	TestArrayIsTaintedWhenSourceIsInserted(core.Source2())         // @Source(ar1)
	TestArrayLiteralContainingSourceIsTainted(core.Source2())      // @Source(ar2)
	TestValueObtainedFromTaintedArrayIsTainted(core.Source2())     // @Source(ar3)
	TestArrayRemainsTaintedWhenSourceIsOverwritten(core.Source2()) // @Source(ar4)
	TestRangeOverArray()
}
