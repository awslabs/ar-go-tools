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

import (
	"fmt"
	"strings"
)

func extract(name string) string {
	// branch on tainted data
	if !strings.HasSuffix(name, ").Error") {
		return ""
	}
	name = name[:len(name)-7]
	if !strings.HasPrefix(name, "(") {
		return ""
	}
	name = name[1:]
	if strings.HasPrefix(name, "*") {
		name = name[1:]
	}
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[:i]
}

func source1() string {
	return "tainted"
}

func sink1(x any) {
	fmt.Println(x)
}

func rec(x string) string {
	// branch on tainted data
	switch x {
	case "":
		return rec("b")
	case "a":
		return rec(x + "b")
	case "b":
		return rec("a")
	case "ab":
		return x
	default:
		return rec(x[1:])
	}
}

func main() {
	x := fmt.Sprintf("%s", rec(rec(source1()))) // @Source(source1)
	y := extract(x)
	// branch on tainted data
	if len(y) > 2 {
		return
	}
	z := extract(extract(y))
	sink1(z) // @Sink(source1)
}
