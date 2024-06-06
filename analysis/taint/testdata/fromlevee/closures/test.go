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

package closures

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func TesCapturedSourceReachesSinkInClosure() func() {
	s0 := core.Source() // @Source(clo1)
	return func() {
		core.Sink("%v", s0) // @Sink(clo1)
	}
}

func TestSourceReachesSinkInClosure() func() {
	return func() {
		s0 := core.Source() // @Source(clo2)
		core.Sink("%v", s0) // @Sink(clo2)
	}
}

func TestAll() {
	TesCapturedSourceReachesSinkInClosure()()
	TestSourceReachesSinkInClosure()()
}
