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
	"fromlevee/arguments"
	basic "fromlevee/basictypes"
	"fromlevee/binop"
	"fromlevee/booleans"
	"fromlevee/callorder"
	"fromlevee/closures"
	"fromlevee/collections"
	"fromlevee/eface"
	"fromlevee/embedding"
	"fromlevee/loops"
	"fromlevee/propagation"
	"fromlevee/store"
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
