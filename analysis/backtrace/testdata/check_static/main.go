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

// Package backtrace defines a dataflow analysis that finds all the backwards
// dataflow paths from an entrypoint. This analysis finds data flows which means
// that a backtrace consists of the data flowing backwards from an argument to
// the "backtracepoint" (entrypoint) call.

package main

import (
	"fmt"
	"math/rand"
	"regexp"
)

func makesRegex(s string, s2 string) *regexp.Regexp {
	regex := fmt.Sprintf("%s+%s", s, s2)
	return regexp.MustCompile(regex)
}

func buildRegex(s string) *regexp.Regexp {
	return regexp.MustCompile(s)
}

func buildRegexWithNonConstant(s string) *regexp.Regexp {
	rval := fmt.Sprintf("%s-%d", s, rand.Int())
	return regexp.MustCompile(rval)
}

func main() {
	regexp.MustCompile("ok")
	buildRegex("ok")
	makesRegex("ok", "good")
	buildRegexWithNonConstant("bad")
}
