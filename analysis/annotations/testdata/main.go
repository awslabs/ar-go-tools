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

import "fmt"

//argot:config _ @SetOptions(log-level=3) configures log-level for all problems

// sink and source annotation are relative to data categories (e.g. in this example bar, io and html)
// Sink(_) means it is always a sink

// bar is a func
//
//argot:function Source(bar) Sink(html) (an annotation documenting this is a source for bar data and a sink of html)
//argot:param x Sink(io) (the parameter x alone is a sink for io data)
func bar(x string) string {
	return "ok " + x
}

// foo is a func
//
//argot:function @Source(io) (this function is a source of io data)
func foo() string {
	return "ok"
}

// superSensitiveFunction
//
//argot:function Sink(_)
func superSensitiveFunction(iWillPrintYouUnencrypted string) {
	fmt.Println(iWillPrintYouUnencrypted) //argot:ignore _
}

// sanitizerOfIo
//
//argot:function Sanitizer(io)
func sanitizerOfIo(s string) string {
	return s
}

// main is main
func main() {
	fmt.Print(bar(foo()))
	superSensitiveFunction(bar(sanitizerOfIo(foo())))
}
