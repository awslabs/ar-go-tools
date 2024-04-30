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

	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/agent-example/datastructs"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/agent-example/log"
	"github.com/awslabs/ar-go-tools/analysis/taint/testdata/agent-example/messaging"
)

func source(id int) string {
	return fmt.Sprintf("tainted-payload-%d", id)
}

func sink(_ any) {}

func main() {
	logger := log.DefaultImpl{}
	msg := datastructs.InstanceMessage{
		CreatedDate: time.Now().String(),
		Destination: "foo",
		MessageId:   strconv.Itoa(rand.Int()),
		Payload:     source(rand.Int()), //@Source(msg)
		Topic:       "bar",
	}

	docState, err := messaging.ParseSendCommandMessage(context.Background(), msg, "tmp", "mds")
	_ = err
	sink(fmt.Errorf(""))  // aliasing in DebugRef instructions might cause this to appear as a sink
	logger.Info(docState) // @Sink(msg)
	logData(logger, docState)
}

func logData(logger log.Logger, data any) {
	logger.Info(data) // @Sink(msg)
}
