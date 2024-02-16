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

// Package sessionplugin simulates the sessionplugin package in the Agent.
package sessionplugin

import (
	"fmt"

	"diodon-agent/datachannel"
)

func ExecuteSessionPlugin() {
	dc, err := getDataChannel()
	if err != nil { //argot:ignore
		fmt.Println(err)
	}
	dc.PerformHandshake()
	fmt.Println(dc.LogReaderId())
}

var getDataChannel = func() (datachannel.IDataChannel, error) {
	logReaderId := "logReaderId"
	retry := func() (interface{}, error) {
		dc, err := datachannel.NewDataChannel(logReaderId)
		if err != nil { //argot:ignore
			return nil, fmt.Errorf("failed to create data channel")
		}
		return dc, nil
	}

	dc, err := retry()
	if err != nil { //argot:ignore
		return nil, fmt.Errorf("failed to create data channel")
	}

	return dc.(datachannel.IDataChannel), nil
}
