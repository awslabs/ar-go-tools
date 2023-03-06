package propagation

import (
	"fromlevee/core"
)

func TestCopyPropagatesTaintFromSrcToDst() {
	s := core.Container{Data: core.Source()} // @Source(bu1)
	b := make([]byte, len(s.Data))
	bytesCopied := copy(b, s.Data)
	core.Sink(bytesCopied)
	core.Sink(b) // @Sink(bu1)
}

func TestCopyDoesNotPropagateTaintFromDstToSrc() {
	s := core.Container{Data: core.Source()} // @Source(bu2)
	data := []byte(s.Data)
	redacted := []byte("<redacted>")
	copy(data, redacted)
	core.Sink(redacted)
}

func TestCopyDoesNotPropagateTaintToReturnedCount() {
	s := core.Container{Data: core.Source()} // @Source(bu3)
	var b []byte
	count := copy(b, s.Data)
	core.Sink(count)
}

func TestAppendPropagatesTaintFromInputValueToInputAndOutputSlices(in, out []string) {
	s := core.Container{Data: core.Source()} // @Source(bu4)
	out = append(in, s.Data)
	core.Sink(in)  // @Sink(bu4)
	core.Sink(out) // @Sink(bu4)
}

func TestAppendPropagatesTaintFromInputSliceToOutputSlice(out []interface{}) {
	safe := "ok"
	s := core.Container{Data: core.Source()} // @Source(bu5)
	in := []interface{}{s.Data}
	out = append(in, safe)
	core.Sink(out) // @Sink(bu5)
	core.Sink(safe)
}

func TestSpreadIntoAppendPropagatesTaintFromValueToSlices(in, out []byte) {
	s := core.Container{Data: core.Source()} // @Source(bu6)
	out = append(in, s.Data...)
	core.Sink(in)  // @Sink(bu6)
	core.Sink(out) // @Sink(bu6)
}

func TestAllBuiltin() {
	TestCopyDoesNotPropagateTaintFromDstToSrc()
	TestCopyPropagatesTaintFromSrcToDst()
	TestCopyDoesNotPropagateTaintToReturnedCount()
	in1 := []string{"ok"}
	out1 := []string{"ok2"}
	TestAppendPropagatesTaintFromInputValueToInputAndOutputSlices(in1, out1)
	out2 := []interface{}{"ok2"}
	TestAppendPropagatesTaintFromInputSliceToOutputSlice(out2)
	in2 := []byte{8, 2}
	out3 := []byte{1, 4}
	TestSpreadIntoAppendPropagatesTaintFromValueToSlices(in2, out3)
}
