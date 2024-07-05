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

package basic

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func BooleansDontPropagateTaint(s *string) {
	is := isSourcey(s)
	core.Sink(is)
}

func isSourcey(_ interface{}) bool {
	// not taking any chances
	return true
}

func IntegersDontPropagateTaint(sources []string) {
	core.Sink(len(sources)) // @Sink(basic) - TODO: levee doesn't propagate taint through integers - should we?
}

func TestAll() {
	s := core.Source() // @Source(basic)
	BooleansDontPropagateTaint(&s)
	IntegersDontPropagateTaint([]string{s})
}
