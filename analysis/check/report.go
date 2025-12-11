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

package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// SoundnessResult is the result of checking the soundness of a single data flow summary.
type SoundnessResult struct {
	// Fn is the qualified name of the summarized function.
	Fn string
	// Want is the summary being checked.
	Want summaries.DetailedSummary
	// IsSound is true if Want is an overapproximation of Got.
	IsSound bool
	// UnprovenMustNotFlows are the must-not-flows unable to be proven sound.
	UnprovenMustNotFlows []Flow
	// Method is the most effective method used for the soundness check.
	Method Method
	// Time is the time spent to calculate the result.
	Time time.Duration
}

func (r SoundnessResult) MarshalJSON() ([]byte, error) {
	b := &bytes.Buffer{}
	raw := rawSoundnessResult{
		Func:                 r.Fn,
		Want:                 rawFlows(r.Want.Flows),
		IsSound:              r.IsSound,
		UnprovenMustNotFlows: funcutil.Map(r.UnprovenMustNotFlows, (Flow).String),
		Method:               string(r.Method),
		TimeSeconds:          time.Duration(r.Time.Seconds()),
	}
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false) // don't escape characters like "<"
	err := enc.Encode(raw)
	res := b.Bytes()
	return res, err
}

func newSoundnessResult(
	g *dataflow.SummaryGraph, res checkResult, want summaries.DetailedSummary, start time.Time, via Method,
) SoundnessResult {
	return SoundnessResult{
		Fn:                   g.Parent.RelString(nil),
		Want:                 want,
		IsSound:              res.isSound,
		UnprovenMustNotFlows: funcutil.Map(res.mustNotFlows, newFlow),
		Method:               via,
		Time:                 time.Since(start),
	}
}

type Flow struct {
	Fn   string
	From summaries.SummaryNode
	To   summaries.SummaryNode
}

func newFlow(f flow) Flow {
	return Flow{
		Fn:   f.from.Graph().Parent.RelString(nil),
		From: newSummaryNode(f.from),
		To:   newSummaryNode(f.to),
	}
}

func (f Flow) String() string {
	return fmt.Sprintf("%s: %s -> %s", f.Fn, f.From, f.To)
}

type rawSoundnessResult struct {
	Func                 string
	Want                 map[string][]string
	Got                  map[string][]string
	IsSound              bool
	UnprovenMustNotFlows []string
	Method               string
	TimeSeconds          time.Duration
}

func rawFlows(flows map[summaries.SummaryNode][]summaries.SummaryNode) map[string][]string {
	res := make(map[string][]string)
	for k, vs := range flows {
		res[k.String()] = make([]string, 0, len(vs))
		for _, v := range vs {
			res[k.String()] = append(res[k.String()], v.String())
		}
	}
	return res
}

// newSummaryNode constructs a summary node from a data flow graph node.
// Panics if gn is invalid since this should be enforced by the visitor.
func newSummaryNode(gn dataflow.GraphNode) summaries.SummaryNode {
	switch gn := gn.(type) {
	case *dataflow.ParamNode:
		f := gn.SsaNode().Parent()
		if recv := f.Signature.Recv(); recv != nil {
			// f is a method and param is a receiver
			if gn.Index() == 0 {
				return summaries.ReceiverSNode{}
			}
			return summaries.ArgumentSNode{Name: gn.SsaNode().Name(), Index: gn.Index() - 1, ObjectPath: ""}
		}
		return summaries.ArgumentSNode{Name: gn.SsaNode().Name(), Index: gn.Index(), ObjectPath: ""}
	case *dataflow.ReturnValNode:
		return summaries.ReturnSNode{Index: gn.Index(), ObjectPath: ""}
	default:
		panic(fmt.Errorf("unexpected graph node type: %v (%T)", gn, gn))
	}
}
