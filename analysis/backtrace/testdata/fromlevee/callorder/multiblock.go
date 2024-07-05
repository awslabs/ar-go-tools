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

// This set of tests is borrowed from go-flow-levee
// Source: https://github.com/google/go-flow-levee/blob/master/internal/pkg/levee/testdata/src/levee_analysistest/example/tests/callorder/multiblock.go

package callorder

import (
	"fmt"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func TestSinkInIfBeforeTaint() {
	w := os.Stdout
	s := core.Source()
	if true {
		core.Sink(w)
	}
	fmt.Fprintf(w, "%v", s)
}

func TestTaintInIfBeforeSink() {
	w := os.Stdout
	s := core.Source() // @Source(mb1)
	if true {
		fmt.Fprintf(w, "%v", s)
	}
	core.Sink(w) // @Sink(mb1)
}

func TestSinkAndTaintInDifferentIfBranches() {
	w := os.Stdout
	s := core.Source()
	if true {
		fmt.Fprintf(w, "%v", s)
	} else {
		core.Sink(w)
	}
}

func TestSinkInIfBeforeTaintInIf() {
	w := os.Stdout
	s := core.Source()
	if true {
		core.Sink(w)
	}
	if true {
		fmt.Fprintf(w, "%v", s)
	}
}

func TestTaintInIfBeforeSinkInIf() {
	w := os.Stdout
	s := core.Source() // @Source(mb2)
	if true {
		fmt.Fprintf(w, "%v", s)
	}
	if true {
		core.Sink(w) // @Sink(mb2)
	}
}

func TestSinkBeforeTaintInSameIfBlock() {
	w := os.Stdout
	s := core.Source1()
	if true {
		core.Sink(w)
		fmt.Fprintf(w, "%v", s)
	}
}

func TestTaintBeforeSinkInSameIfBlock() {
	w := os.Stdout
	s := core.Source() // @Source(mb3)
	if true {
		fmt.Fprintf(w, "%v", s)
		core.Sink(w) // @Sink(mb3)
	}
}

func TestSinkInNestedIfBeforeTaint() {
	w := os.Stdout
	s := core.Source()
	if true {
		if true {
			core.Sink(w)
		}
	}
	fmt.Fprintf(w, "%v", s)
}

func TestTaintInNestedIfBeforeSink() {
	w := os.Stdout
	s := core.Source() // @Source(mb40, mb41, mb42)
	if true {
		if true {
			fmt.Fprintf(w, "%v", s)
			core.Sink(w) // @Sink(mb40)
		}
		core.Sink(w) // @Sink(mb41)
	}
	core.Sink(w) // @Sink(mb42)
}

func TestSinkAndTaintInSeparateSwitchCases() {
	w := os.Stdout
	s := core.Source()
	switch "true" {
	case "true":
		core.Sink(w)
	case "false":
		fmt.Fprintf(w, "%v", s)
	}
}

func TestSinkAfterTaintInSwitch() {
	w := os.Stdout
	s := core.Source() // @Source(mb5)
	switch "true" {
	case "true":
		fmt.Fprintf(w, "%v", s)
	}
	core.Sink(w) // @Sink(mb5)
}

func TestSinkAfterTaintInFor() {
	w := os.Stdout
	sources := make([]string, 10)
	for i := range sources {
		sources[i] = core.Source() // @Source(mb6)
	}

	// branch on tainted data
	for i := 0; i < len(sources); i++ {
		fmt.Fprintf(w, "%v", sources[i])
	}
	core.Sink(w) // @Sink(mb6)
}

func TestAllMultiBlock() {
	TestSinkInIfBeforeTaint()
	TestTaintInIfBeforeSink()
	TestSinkAndTaintInDifferentIfBranches()
	TestSinkInIfBeforeTaintInIf()
	TestTaintInIfBeforeSinkInIf()
	TestSinkBeforeTaintInSameIfBlock()
	TestTaintBeforeSinkInSameIfBlock()
	TestSinkInNestedIfBeforeTaint()
	TestTaintInNestedIfBeforeSink()
	TestSinkAndTaintInSeparateSwitchCases()
	TestSinkAfterTaintInSwitch()
	TestSinkAfterTaintInFor()
}
