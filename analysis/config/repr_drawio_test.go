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
	"reflect"
	"testing"

	"golang.org/x/exp/slices"
)

func TestSimpleFlowWithOption(t *testing.T) {
	_, config, err := loadFromTestDir("example.drawio.xml")
	_, config2, err2 := loadFromTestDir("example.drawio.yaml")
	if config == nil || err != nil || config2 == nil || err2 != nil {
		t.Fatalf("error: %v, %v", err, err2)
	}
	if !reflect.DeepEqual(config.Options, config2.Options) {
		fmt.Printf("Config options:\n.yml: %+v\n", config2.Options)
		fmt.Printf(".xml: %+v\n", config.Options)
		t.Fatalf("configs from xml and yaml differ in global options")
	}
	if !slices.Equal(config.UserSpecs, config2.UserSpecs) {
		t.Fatalf("configs from xml and yaml do not have the same dataflow specs")
	}
	n := len(config2.TaintTrackingProblems)
	if n != 1 || len(config.TaintTrackingProblems) != n {
		t.Fatalf("configs from xml and yaml do not have the same number of taint tracking problems (1)")
	}

	tp1 := config.TaintTrackingProblems[0]
	tp2 := config2.TaintTrackingProblems[0]

	if len(tp1.Sinks) != 1 || len(tp2.Sinks) != 1 ||
		len(tp2.Sources) != 1 || len(tp1.Sources) != 1 ||
		len(tp2.Sanitizers) != 1 || len(tp2.Sources) != 1 {
		t.Fatalf("configs do not define the same taint tracking problem")
	}

	if tp1.Sources[0].Package != tp2.Sources[0].Package || tp1.Sources[0].Method != tp2.Sources[0].Method {
		t.Fatalf("sources %v and %v do not match", tp1.Sources[0], tp2.Sources[0])
	}

	if tp1.Sinks[0].Package != tp2.Sinks[0].Package || tp1.Sinks[0].Method != tp2.Sinks[0].Method {
		t.Fatalf("sources %v and %v do not match", tp1.Sinks[0], tp2.Sinks[0])
	}

	if tp1.Sanitizers[0].Package != tp2.Sanitizers[0].Package || tp1.Sanitizers[0].Method != tp2.Sanitizers[0].Method {
		t.Fatalf("sources %v and %v do not match", tp1.Sanitizers[0], tp2.Sanitizers[0])
	}
}
