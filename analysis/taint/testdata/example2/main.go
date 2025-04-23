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
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strconv"
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

type PayloadStruct struct {
	Payload string
	Id      string
}

type contentStruct struct {
	Type  string
	Value string
}

type ParsedPayload struct {
	Id       string
	Contents contentStruct
}

func parseMessage(ct context.Context, payload PayloadStruct) (ParsedPayload, error) {
	if _, ok := ct.Deadline(); ok {
		var contents *contentStruct
		err := json.Unmarshal([]byte(payload.Payload), contents)
		if err != nil {
			return ParsedPayload{}, err
		}
		return ParsedPayload{
				Contents: *contents,
				Id:       payload.Id,
			},
			nil
	}
	return ParsedPayload{}, fmt.Errorf("not enough time")
}

func sanitizer(contents contentStruct) contentStruct {
	return contentStruct{
		Type:  contents.Type,
		Value: strings.ToLower(contents.Value),
	}
}

func sanitizerStr(id string) string {
	return strings.ToUpper(id)
}

func parseAndSanitizeMsg(ct context.Context, payload PayloadStruct) (ParsedPayload, error) {
	if _, ok := ct.Deadline(); ok {
		var contents *contentStruct
		err := json.Unmarshal([]byte(payload.Payload), contents)
		if err != nil {
			return ParsedPayload{}, err
		}
		return ParsedPayload{
				Contents: sanitizer(*contents),
				Id:       payload.Id,
			},
			nil
	}
	return ParsedPayload{}, fmt.Errorf("not enough time")
}

func parsingProxy(payload PayloadStruct) (ParsedPayload, error) {
	context := context.Background()
	return parseMessage(context, payload)
}

func parsingSanitizingProxy(payload PayloadStruct) (ParsedPayload, error) {
	context := context.Background()
	return parseAndSanitizeMsg(context, payload)
}

func generateAndParseMessage() {
	payload := fmt.Sprintf("{\"type\":\"json\",\"Value\":\"{\\\"x\\\":\\\"%s\\\"}\"}", source1()) // @Source(source2)
	messageId := "id-" + strconv.Itoa(rand.Int())
	payloadStruct := PayloadStruct{Payload: payload, Id: messageId}
	doc, err := parsingProxy(payloadStruct)
	if err != nil {
		panic("error processing doc")
	}
	sink1(doc.Contents.Value) // @Sink(source2)
}

func genParseAndSanitizeMessage() {
	payload := fmt.Sprintf("{\"type\":\"json\",\"Value\":\"{\\\"x\\\":\\\"%s\\\"}\"}", source1())
	messageId := "id-" + strconv.Itoa(rand.Int())
	payloadStruct := PayloadStruct{Payload: payload, Id: messageId}
	validateDoc, err := parsingSanitizingProxy(payloadStruct)
	if err != nil {
		panic("error processing doc")
	}
	sink1(validateDoc.Contents.Value)
}

func extractAndRecurse() {
	x := fmt.Sprintf("%q", rec(rec(source1()))) // @Source(source1)
	y := extract(x)
	// branch on tainted data
	if len(y) > 2 {
		return
	}
	z := extract(extract(y))
	sink1(z) // @Sink(source1)
}

func main() {
	extractAndRecurse()
	generateAndParseMessage()
	genParseAndSanitizeMessage()
}
