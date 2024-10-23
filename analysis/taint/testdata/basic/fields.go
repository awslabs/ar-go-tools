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
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
)

type Example struct {
	SourceField string
	OtherData   string
}

func testField() {
	s := Example{SourceField: "tainted", OtherData: "not tainted"}
	s2 := "ok"
	s3 := passing(s.SourceField, s2) // @Source(field2) is the closest to the sink
	s4 := fmt.Sprintf("%s", s3)
	sink1(s4) // tainted data reaches this @Sink(field1,field2)
}

type Sample struct {
	Secret    string
	OtherData string
}

func testField2() {
	var payload Sample
	err := json.Unmarshal([]byte("{\"Secret\":\"sdfds\"}"), &payload)
	if err != nil {
		return
	}

	decodedAESKey, err := base64.StdEncoding.DecodeString(payload.OtherData)
	if err != nil {
		return
	}

	newCipher, err := aes.NewCipher(decodedAESKey)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(newCipher)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()
	creds, err := base64.StdEncoding.DecodeString(payload.Secret) // @Source(secret)
	if err != nil {
		return
	}
	sink2(fmt.Sprintf("%s-%d", creds, nonceSize)) // @Sink(secret)
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

type ExampleData struct {
	SinkField string
	OtherData string
}

func testStoreTaintedDataInField() {
	x := source1() // @Source(storeTaintedData)
	s := ExampleData{OtherData: "not tainted", SinkField: "not tainted"}
	s.SinkField = x // @Sink(storeTaintedData)
	println(s.SinkField)
}

func genExample() Example {
	s := "tainted" + strconv.Itoa(rand.Int())
	o := "ok"
	return Example{
		SourceField: s,
		OtherData:   o,
	}
}

func testSourceFieldInSinkField() {
	x := genExample()
	s := ExampleData{OtherData: "not tainted", SinkField: "not tainted"}
	s.SinkField = x.SourceField // @Source(sourceFieldInSinkField) @Sink(sourceFieldInSinkField)
	println(s.SinkField)
}
