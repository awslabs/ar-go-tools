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
	"encoding/json"
	"fmt"
	"sync"
)

func TestJsonUnmarshal() {
	x := source1() // @Source(TestJsonUnmarshal)
	s := "{\"Data\": \"x\", \"Other\":" + x.Other + "}"
	y := T{}
	json.Unmarshal([]byte(s), &y)
	sink1(y.Data) // @Sink(TestJsonUnmarshal)
}

func TestJsonMarshal() {
	x := source1() // @Source(TestJsonMarshal)
	s, err := json.Marshal(x)
	if err != nil {
		return
	}
	sink1(string(s)) // @Sink(TestJsonMarshal)
}

func TestSyncDoOnce() {
	o := &sync.Once{}
	x := source1() // @Source(TestSyncDoOnce)
	o.Do(func() {
		sink2(x) // @Sink(TestSyncDoOnce)
	})
}

func TestFmtErrorf() {
	x := source3() // @Source(TestFmtErrorf)
	eTainted := fmt.Errorf("error: %s", x)
	sink2(eTainted) // @Sink(TestFmtErrorf)
	y := genStr()
	eNotTainted := fmt.Errorf("error: %s", y)
	sink2(eNotTainted) // @Sink(TestFmtErrorf) -> false positive because all fmt.Errorf output are spuriously aliased!
	// see stdlib-no-effect-constraint test suite for a (possibly unsound) option to avoid that!
}

func main() {
	TestJsonUnmarshal()
	TestJsonMarshal()
	TestSyncDoOnce()
	TestFmtErrorf()
}
