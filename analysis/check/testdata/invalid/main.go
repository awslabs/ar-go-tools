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

// Package main holds fixtures whose top-level checkSummary call is expected to be rejected
// outright (an Error result), as opposed to testdata/basic, which holds fixtures whose soundness
// is actually evaluated.
package main

// higherOrderDirect has a function-typed parameter, so it is higher-order per the paper's
// definition (an input or output access path that resolves to a function type).
func higherOrderDirect(f func(), x string) string {
	return x
}

// higherOrderReturn returns a function value directly.
func higherOrderReturn(x string) func() {
	return func() {}
}

// higherOrderBox has a field that resolves to a function type.
type higherOrderBox struct {
	H func()
	V string
}

// higherOrderField has a parameter whose struct type has a field that resolves to a function
// type, so it is higher-order even though the parameter's own top-level type is not a function.
func higherOrderField(b *higherOrderBox) string {
	return b.V
}

// higherOrderMap has a parameter whose type is a map with a function-typed value, so it is
// higher-order even though map is not a function type itself.
func higherOrderMap(m map[int]func()) int {
	return len(m)
}

func main() {
	higherOrderDirect(func() {}, "x")
	higherOrderReturn("x")()
	higherOrderField(&higherOrderBox{H: func() {}, V: "x"})
	higherOrderMap(map[int]func(){})
}
