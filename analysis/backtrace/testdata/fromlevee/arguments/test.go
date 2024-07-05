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

package arguments

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func TestSourceFromParamByReference(s *core.Container) {
	core.Sink("Source in the parameter %v", s) // @Sink(arg)
}

func TestSourceMethodFromParamByReference(s *core.Container) {
	core.Sink("Source in the parameter %v", s.Data) // @Sink(arg)
}

func TestSourceFromParamByReferenceInfo(s *core.Container) {
	core.Sink(s) // @Sink(arg)
}

func TestSourceFromParamByValue(s core.Container) {
	core.Sink("Source in the parameter %v", s) // @Sink(arg)
}

func TestUpdatedSource(s *core.Container) {
	s.Data = "updated"
	core.Sink("Updated %v", s) // @Sink(arg)
}

func TestSourceFromAPointerCopy(s *core.Container) {
	cp := s
	core.Sink("Pointer copy of the source %v", cp) // @Sink(arg)
}

func TestAll() {
	s := core.Source3() // @Source(arg)
	TestSourceFromAPointerCopy(&s)
	TestSourceFromParamByReference(&s)
	TestSourceMethodFromParamByReference(&s)
	TestSourceFromParamByReferenceInfo(&s)
	TestSourceFromParamByValue(s)
	TestUpdatedSource(&s)
}
