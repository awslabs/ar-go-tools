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

package embedding

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

type EmbedsSource struct {
	core.Container
}

type EmbedsSourcePointer struct {
	*core.Container
}

func TestStructThatEmbedsSourceIsSource() {
	core.Sink(EmbedsSource{core.Source3()}) // @Source(em1) @Sink(em1)
}

func TestStructThatEmbedsSourcePointerIsSource() {
	s := core.Source3()                // @Source(em2)
	core.Sink(EmbedsSourcePointer{&s}) //  @Sink(em2)
}

func TestEmbeddedSourceIsSource() {
	s := core.Source3()             // @Source(em3)
	core.Sink(EmbedsSource{s}.Data) // @Sink(em3)
}

func TestEmbeddedSourcePointerIsSource() {
	s := core.Source3()                     //  @Source(em4)
	core.Sink(EmbedsSourcePointer{&s}.Data) // @Sink(em4)
}

func TestAll() {
	TestStructThatEmbedsSourceIsSource()
	TestStructThatEmbedsSourcePointerIsSource()
	TestEmbeddedSourceIsSource()
	TestEmbeddedSourcePointerIsSource()
}
