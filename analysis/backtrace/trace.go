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
	"fmt"
	"go/token"
	"strings"

	df "github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// Trace represents a dataflow path (sequence of nodes) out of an analysis
// entrypoint.
//
// The first node in the trace is the origin of the data flow.
//
// The last node in the trace is an argument to the backtrace entrypoint function
// defined in the config.
type Trace []TraceNode

func (t Trace) String() string {
	if len(t) == 0 {
		return "<empty trace>"
	}

	first := fmt.Sprintf("%v from %v:\n", formatutil.Bold("Trace"), t[0].String())
	var rest []TraceNode
	if len(t) > 1 {
		rest = t[1:]
	}

	b := &strings.Builder{}
	if _, err := b.WriteString(first); err != nil {
		panic(fmt.Errorf("failed to write first node to trace string: %v", err))
	}
	for i, tn := range rest {
		if _, err := b.WriteString("\t"); err != nil {
			panic(fmt.Errorf("failed to write to trace string: %v", err))
		}
		if _, err := b.WriteString(tn.String()); err != nil {
			panic(fmt.Errorf("failed to write trace node %v to string: %v", tn, err))
		}

		if i == len(rest)-1 {
			continue
		}
		if _, err := b.WriteString("\n"); err != nil {
			panic(fmt.Errorf("failed to write to trace string: %v", err))
		}
	}

	return b.String()
}

// Key generates a unique key for trace t.
func (t Trace) Key() df.KeyType {
	keys := make([]string, 0, len(t))
	for _, node := range t {
		keys = append(keys, node.LongID())
	}

	return strings.Join(keys, "_")
}

// TraceNode represents a node in the trace.
type TraceNode struct {
	df.GraphNode
	Pos token.Position
}

func (n TraceNode) String() string {
	if n.GraphNode == nil {
		return ""
	}

	return fmt.Sprintf("%v at %v", n.GraphNode.String(), n.Pos)
}
