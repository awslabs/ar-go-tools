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

type Example struct {
	SourceField string
	OtherData   string
}

func testField() {
	s := Example{SourceField: "tainted", OtherData: "not tainted"} // @Source(field1)
	s2 := "ok"
	s3 := passing(s.SourceField, s2) // @Source(field2) is the closest to the sink
	s4 := fmt.Sprintf("%s", s3)
	sink1(s4) // tainted data reaches this @Sink(field1,field2)
}

type SourceStruct struct {
	Source1 string
}
type SourceEmbed struct {
	SourceStruct
	OtherData string
}

func testFieldEmbedded() {
	s1 := SourceEmbed{SourceStruct: SourceStruct{Source1: "tainted"}, OtherData: "not tainted"} // @Source(embedded1)
	s2 := "ok"
	s3 := passing(s1.Source1, s2) // @Source(embedded2)
	s4 := fmt.Sprintf("%s", s3)
	sink1(s4) // @Sink(embedded1,embedded2)
}
