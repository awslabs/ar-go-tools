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
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"agent-example/datastructs"
	"agent-example/messaging"
)

func sink(v any) {
	fmt.Println(v)
}

func source(id int) string {
	return fmt.Sprintf("tainted-payload-%d", id)
}

func main() {
	msg := datastructs.InstanceMessage{
		CreatedDate: time.Now().String(),
		Destination: "foo",
		MessageId:   strconv.Itoa(rand.Int()),
		Payload:     source(rand.Int()), //@Source(msg)
		Topic:       "bar",
	}

	docState, _ := messaging.ParseSendCommandMessage(context.Background(), msg, "tmp", "mds")
	sink(docState) // @Sink(msg)
}
