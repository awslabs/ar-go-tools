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

package backtrace

import (
	"strings"

	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
)

// Trace represents a dataflow path (sequence of nodes) out of an analysis
// entrypoint.
//
// The first node in the trace is the origin of the data flow.
//
// The last node in the trace is an argument to the backtrace entrypoint function
// defined in the config.
type Trace []*df.VisitorNode

// Key generates a unique key for trace t.
func (t Trace) Key() df.KeyType {
	keys := make([]string, 0, len(t))
	for _, node := range t {
		keys = append(keys, string(node.Key()))
	}

	return strings.Join(keys, "_")
}
