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

package callorder

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

// This type should *not* be identified as a Source.
type key struct {
	name string
}

func (k *key) Name() string {
	return k.name
}

func newKey() *key {
	return &key{
		name: "",
	}
}

func TestDoesNotReachSinkAfterSourceThroughValueCreatedBeforeSource() {
	// Taint should not propagate to this value.
	k := newKey()

	_ = map[string]string{"x": core.Source()}[k.name]

	core.Sink(k.Name())
}

func TestDoesNotReachSinkInIfBeforeSourceThroughValueCreatedBeforeSource() {
	// Taint should not propagate to this value.
	k := newKey()

	if true {
		core.Sink(k.Name())
	}

	_ = map[string]string{"x": core.Source()}[k.name]
}

func TestValueDeclaredBeforeSourceIsTainted() {
	var x interface{} = core.Innocuous()
	x = core.Source() // @Source(bs1)
	core.Sink(x)      // @Sink(bs1)
}

func TestSliceDeclaredBeforeSourceIsTainted() {
	xs := []interface{}{nil}
	xs[0] = core.Source() // @Source(bs2)
	core.Sink(xs)         // @Sink(bs2)
}

func TestAllBeforeSource() {
	TestDoesNotReachSinkAfterSourceThroughValueCreatedBeforeSource()
	TestDoesNotReachSinkInIfBeforeSourceThroughValueCreatedBeforeSource()
	TestValueDeclaredBeforeSourceIsTainted()
	TestSliceDeclaredBeforeSourceIsTainted()
}
