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

package config

import (
	"fmt"
	"testing"
)

func TestSimpleFlowWithOption(t *testing.T) {
	_, config, err := loadFromTestDir(t, "example.drawio.xml")
	_, config2, err2 := loadFromTestDir(t, "example.drawio.yaml")
	if config == nil || err != nil || config2 == nil || err2 != nil {
		t.Fatalf("error: %v, %v", err, err2)
	}
	if config.Options != config2.Options {
		fmt.Printf("Config options:\n.yml: %+v\n", config2.Options)
		fmt.Printf(".xml: %+v\n", config.Options)
		t.Fatalf("configs from xml and yaml differ")
	}
}
