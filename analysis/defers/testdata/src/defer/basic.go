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

package main

// Functions that substitute for arbitrary behavior
func arbitrary() bool  { return false }
func external(int) int { return 0 }

// Basic function, one defer, one return
func f1() int {
	i := 1
	defer func() { i = 3 }()
	i = 4
	return external(i)
}

// Test a branch before a Defer. Should be a return with no stacks, and one with one stack
func f2() int {
	if arbitrary() {
		return 0
	}
	defer func() {}()
	return 1
}

// Test loop with no defer
func f3() int {
	i := 1
	defer func() { println(i) }()
	i = 4
	if arbitrary() {
		external(5)
	}
	for i = 0; i < 10; i++ {
		external(i)
	}
	defer external(2)
	return i
}

// Should be 3 possible stacks.
func f4() (err error) {
	if arbitrary() {
		if arbitrary() {
			defer external(3)
		} else {
			defer external(4)
		}
	}
	return nil
}

// Unbounded set, should fail
func f5() (err error) {
	for i := 0; i < 10; i++ {
		//goland:noinspection GoDeferInLoop
		defer func() {
			err = *new(error)
		}()
	}
	return nil
}

// Test an exponential blowup (2^4 = 16 sets)
func f6() (err error) {
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	return nil
}

// Test a branch with a Defer.
func f7() int {
	if arbitrary() {
		defer external(3)
	}
	defer func() {}()
	return 1
}
