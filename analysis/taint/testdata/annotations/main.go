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

// Specific problem-level config options can be set in annotations
//argot:config lim SetOptions(max-alarms=2,unsafe-max-depth=2)

// bar
// It is also a source for the problem hybridDef also defined in the config.json
// The sink for that problem is fmt.Println
//
//argot:function Source(ex1, ex2, hybridDef)
func bar() string {
	return strconv.Itoa(rand.Int()) + "-taint"
}

//argot:function Sink(ex1,lim)
func sink(s string) {
	fmt.Print(s)
}

//argot:function Source(lim)
func source() string {
	return strconv.Itoa(rand.Int()) + "tainted"
}

func justPassing(s string) string {
	return fmt.Sprintf("wrap(%s)", s)
}

func passingThrough(s string) string {
	return justPassing(s)
}

func amending(s string) string {
	return passingThrough(s) + strconv.Itoa(rand.Int())
}

func amending2(s string) string {
	return amending(s) + strconv.Itoa(rand.Int())
}

//argot:function Sanitizer(ex1)
func sanitizer(s string) string {
	return strings.ReplaceAll(s, "%", "_")
}

//argot:param unsafe Sink(ex2)
func sinkOnSecondArg(safe string, unsafe string) {
	fmt.Println(unsafe + safe) // @Sink(hybridDef)
}

//argot:param clean Sanitizer(_)
func sanitizeSecondArg(safe string, clean string) string {
	return clean + safe
}

func main() {
	s := bar()                       // @Source(ex1,ex2,hybridDef)
	sink(s)                          //  @Sink(ex1)
	sinkOnSecondArg(s, "ok")         // only second argument of this is a sink
	sinkOnSecondArg("ok", s)         // @Sink(ex2)
	sink(sanitizeSecondArg(s, "ok")) // @Sink(ex1)
	sink(sanitizeSecondArg("ok", s))
	sink(sanitizer(s))
	fmt.Println(s)            // @Sink(hybridDef)
	sink(amending2(source())) // no alarm because of the unsafe config option set to 2 for the lim problem
}
