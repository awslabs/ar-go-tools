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

package store

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/core"
)

func TestStoringToTaintedAddrDoesNotTaintStoredValue() {
	myChan := make(chan string)
	s := core.Container{Data: core.Source()}
	recv := <-myChan
	s.Data = recv
	core.Sink(recv)
	core.Sink(myChan)
}
