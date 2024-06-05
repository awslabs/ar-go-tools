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

package main

import (
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/arguments"
	basic "github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/basictypes"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/binop"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/booleans"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/callorder"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/closures"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/collections"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/eface"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/embedding"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/loops"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/propagation"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/fromlevee/store"
)

func main() {
	// Arguments
	arguments.TestAll() // 6 tests
	// Basic Types
	basic.TestAll() // 2 tests
	// Bools
	booleans.TestDoNotTraverseToBoolean()
	// Binop
	binop.TestAll()
	// Closures
	closures.TestAll()
	// Collections
	collections.TestAllArrays()
	collections.TestAllChan()
	collections.TestAllMap()
	collections.TestAllSlices()
	// Eface
	eface.TestAll() // 2 tests
	// Embedding
	embedding.TestAll()
	// Loops
	loops.TestAll() // 8 tests
	// Propagation
	propagation.TestAllBuiltin()
	// Store
	store.TestStoringToTaintedAddrDoesNotTaintStoredValue()
	// Before Source
	callorder.TestAllBeforeSource() // 4 tests
	// Singleblock
	callorder.TestAllSingleBlock() // 3 tests
	// Multiblock
	callorder.TestAllMultiBlock() // 12 tests
	// Colocation
	callorder.TestAllColocation() // 3 tests
}
