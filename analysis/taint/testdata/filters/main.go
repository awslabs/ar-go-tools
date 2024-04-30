// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// This is an example where:
// - we have interfaces and their implementation produce sensitive data
// - data flows through references and calling the implementation of the interface
package main

import (
	"fmt"
	"math/rand"
	"strconv"
)

func generateWithError() (string, error) {
	if rand.Int() > 20 {
		return source(), nil // @Source(gErr)
	} else {
		return "ok", fmt.Errorf("generation failure")
	}
}

func generateWithFlag() (string, bool) {
	if rand.Int() > 20 {
		return source(), false // @Source(gBool)
	} else {
		return "ok", true
	}
}

func handleErr(e error) {
	sink(e) // not reachable with the config filtering errors
}

// the config contains:
// filters:
//   - type: "error"
func testErrorFiltered() {
	b, e := generateWithError()
	if e != nil {
		handleErr(e)
	}
	s := sanitize(b)
	sink(s) // sanitized
}

// the config contains:
// filters:
//   - type: "bool"
func testBoolFiltered() {
	b, flag := generateWithFlag()
	if !flag {
		doSth(flag, "res")
	} else {
		doSth2(flag, b)
	}
}

func doSth(b bool, s string) {
	sink(b) // not reachable with the config filtering booleans
	sink(s)
}

func doSth2(b bool, s string) {
	sink(b) // not reachable with the config filtering booleans
	sink(s) // @Sink(gBool)
}

func main() {
	testErrorFiltered()
	testBoolFiltered()

}

func sink(_ ...any) {

}

func source() string {
	return "tainted" + strconv.Itoa(rand.Int())
}

func sanitize(s string) string {
	return fmt.Sprintf("<%s>", s)
}
