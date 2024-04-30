// Copyright 2020 Google LLC
// Modifications Copyright Amazon.com, Inc. or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package propagation

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
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
