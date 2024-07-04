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
	"math/rand"
	"strconv"
	"strings"
)

// bar
//
//argot:function Source(ex1,ex2)
func bar() string {
	return strconv.Itoa(rand.Int()) + "-taint"
}

//argot:function Sink(ex1)
func sink(s string) {
	fmt.Print(s)
}

//argot:function Sanitizer(ex1)
func sanitizer(s string) string {
	return strings.ReplaceAll(s, "%", "_")
}

//argot:param unsafe Sink(ex2)
func sinkOnSecondArg(safe string, unsafe string) {
	fmt.Println(unsafe + safe)
}

//argot:param clean Sanitizer(_)
func sanitizeSecondArg(safe string, clean string) string {
	return clean + safe
}

func main() {
	s := bar()                       // @Source(ex1,ex2)
	sink(s)                          //  @Sink(ex1)
	sinkOnSecondArg(s, "ok")         // only second argument of this is a sink
	sinkOnSecondArg("ok", s)         // @Sink(ex2)
	sink(sanitizeSecondArg(s, "ok")) // @Sink(ex1)
	sink(sanitizeSecondArg("ok", s))
	sink(sanitizer(s))
}
