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

//go:build go1.21

package taint_test

import "testing"

func TestCrossFunctionBuiltins121(t *testing.T) {
	t.Parallel()
	runTest(t, "builtins_121", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionBuiltins121_SummarizeOnDemand(t *testing.T) {
	t.Parallel()
	runTest(t, "builtins_121", []string{"helpers.go"}, true, noErrorExpected)
}

func TestCrossFunctionStdlib121(t *testing.T) {
	t.Parallel()
	runTest(t, "stdlib_121", []string{"helpers.go"}, false, noErrorExpected)
}

func TestCrossFunctionStdlib121_SummarizeOnDemand(t *testing.T) {
	t.Parallel()
	runTest(t, "stdlib_121", []string{"helpers.go"}, true, noErrorExpected)
}
