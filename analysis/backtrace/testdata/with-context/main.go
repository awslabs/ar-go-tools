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
	"strings"
)

type wrappedString struct {
	Content string
}

type wrappedStringProducer interface {
	source() wrappedString
}

type fooProducer struct {
	I int `levee:"source"`
}

func (f fooProducer) source() wrappedString {
	if f.I > 0 && f.I < 10 {
		return wrappedString{Content: strings.Repeat("x", f.I)}
	} else {
		return wrappedString{Content: ""}
	}

}

func fetchAndPut(stringProducer wrappedStringProducer, s *string) {
	*s = stringProducer.source().Content // @Source(calledInFetchAndPut)
}

func sink(s string) {
	fmt.Println(s)
}

func main() {
	var s string
	x := fooProducer{I: 1}
	fetchAndPut(x, &s)
	sink(s) // @Sink(calledInFetchAndPut)
	test2()
}

// Second example

func test2() {
	w := fooProducer{1}
	s := w.source() // Ignored because of context: "fetchAndPut" in the config.yaml
	e := f(s, "ok")
	sink(e)
}

func f(s wrappedString, e string) string {
	return g(s.Content, e, e+s.Content) + h(e)
}

func g(a string, b string, c string) string {
	return a + h(b) + c
}

func h(a string) string {
	return fmt.Sprintf("%s", a)
}
