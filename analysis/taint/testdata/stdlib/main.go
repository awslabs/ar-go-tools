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

func main() {
	TestJsonUnmarshal()
	TestJsonMarshal()
	TestSyncDoOnce()
}
