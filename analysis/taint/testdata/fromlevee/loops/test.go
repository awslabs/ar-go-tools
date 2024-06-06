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

package loops

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func TestTaintInThenBlockInLoopSinkAfterLoop() {
	var e interface{}
	for true {
		if true {
			e = core.Source() // @Source(lo1)
		} else {
			e = nil
		}
	}
	core.Sink(e) // @Sink(lo1)
}

func TestTaintInElseBlockInLoopSinkAfterLoop() {
	var e interface{}
	for true {
		if true {
			e = nil
		} else {
			e = core.Source() // @Source(lo2)
		}
	}
	core.Sink(e) // @Sink(lo2)
}

func TestTaintInThenBlockSinkInElseBlockInLoop() {
	var e interface{}
	for true {
		if true {
			e = core.Source() // @Source(lo3)
		} else {
			core.Sink(e) // @Sink(lo3)
		}
	}
}

func TestTaintInElseBlockSinkInThenBlockInLoop() {
	var e interface{}
	for true {
		if true {
			e = core.Source() // @Source(lo4)
		} else {
			core.Sink(e) // @Sink(lo4)
		}
	}
}

func TestTaintInNestedConditionalInLoop() {
	var e interface{}
	for true {
		if true {
			if true {
				e = nil
			} else {
				e = core.Source() // @Source(lo5)
			}
		} else {
			e = nil
		}
	}
	core.Sink(e) // @Sink(lo5)
}

func TestTaintPropagationOverMultipleIterations() {
	var e1 interface{}
	var e2 interface{}
	for true {
		if true {
			e1 = core.Source() // @Source(lo6)
		} else {
			e2 = e1
		}
	}
	core.Sink(e1) // @Sink(lo6)
	core.Sink(e2) // @Sink(lo6)
}

func TestTaintPropagationOverMultipleIterationsWithNestedConditionals() {
	var e1 interface{}
	var e2 interface{}
	var e3 interface{}
	var e4 interface{}
	for true {
		if true {
			e1 = core.Source() // @Source(lo7)
		} else {
			if true {
				e4 = e3
			} else {
				e3 = e2
			}
			e2 = e1
		}
	}
	core.Sink(e1) // @Sink(lo7)
	core.Sink(e2) // @Sink(lo7)
	core.Sink(e3) // @Sink(lo7)
	core.Sink(e4) // @Sink(lo7)
}

func TestSourceOverwrittenBeforeLoopExit() {
	var e interface{}
	for true {
		if true {
			e = nil
		} else {
			e = core.Source()
		}
		e = nil
	}
	core.Sink(e)
}

func TestAll() {
	TestTaintInThenBlockInLoopSinkAfterLoop()
	TestTaintInElseBlockInLoopSinkAfterLoop()
	TestTaintInThenBlockSinkInElseBlockInLoop()
	TestTaintInElseBlockSinkInThenBlockInLoop()
	TestTaintInNestedConditionalInLoop()
	TestTaintPropagationOverMultipleIterations()
	TestTaintPropagationOverMultipleIterationsWithNestedConditionals()
	TestSourceOverwrittenBeforeLoopExit()
}
