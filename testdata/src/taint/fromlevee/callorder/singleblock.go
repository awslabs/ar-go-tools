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

package callorder

// This set of tests is borrowed from go-flow-levee
// https://github.com/google/go-flow-levee/blob/master/internal/pkg/levee/testdata/src/levee_analysistest/example/tests/callorder/singleblock.go

import (
	"fmt"
	"io"
	"os"

	"fromlevee/core"
)

func TestTaintBeforeSinking(w io.Writer) {
	s := core.Source() // @Source(sb1)
	_, _ = fmt.Fprintf(w, "%v", s)
	core.Sink(w) // @Sink(sb1)
}

func TestSinkBeforeTainting(w io.Writer) {
	s := core.Source()
	core.Sink(w)
	_, _ = fmt.Fprintf(w, "%v", s)
}

func TestSinkBeforeAndAfterTainting(w io.Writer) {
	s := core.Source() // @Source(sb2)
	core.Sink(w)
	_, _ = fmt.Fprintf(w, "%v", s)
	core.Sink(w) // @Sink(sb2)
}

func TestAllSingleBlock() {
	TestTaintBeforeSinking(os.Stdout)
	TestSinkBeforeTainting(os.Stdout)
	TestSinkBeforeAndAfterTainting(os.Stdout)
}
