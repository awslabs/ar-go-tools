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

const somePredefinedPattern = "[a-zA-Z]+"
const someOtherPattern = "[0-9]*"

var initPattern = regexp.MustCompile(
	fmt.Sprintf("{{\\s*((?:%s|%s)[\\w-./]+)\\s*}}", somePredefinedPattern, someOtherPattern),
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

func makeRegexFromConst(s string) *regexp.Regexp {
	pat := fmt.Sprintf("(%s)%s*", s, somePredefinedPattern)
	return regexp.MustCompile(pat)
}

func makeRegexFromStaticArray() *regexp.Regexp {
	x := [2]string{}
	x[0] = "ok"
	x[1] = "[A-Z]+"
	return regexp.MustCompile(fmt.Sprintf("%s\\.%s", x[0], x[1]))
}

func makeRegexFromStaticArrayNotStaticData(s string) *regexp.Regexp {
	a := [1]string{}
	a[0] = fmt.Sprintf("%s-%d", s, rand.Int())
	x := [2]string{}
	x[0] = "ok"
	x[1] = a[0]
	return regexp.MustCompile(fmt.Sprintf("%s\\.%s", x[0], x[1]))
}

func main() {
	regexp.MustCompile("ok")
	buildRegex("ok")
	makesRegex("ok", "good")
	buildRegexWithNonConstant("bad")
	makeRegexFromConst("ok")
	makeRegexFromStaticArray()
	makeRegexFromStaticArrayNotStaticData("test")
	if initPattern.MatchString("test") {
		fmt.Println("ok")
	}
}
