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
)

// SoundnessResult is the result of checking the soundness of a single data flow summary.
type SoundnessResult struct {
	Name     string                            // Name is the name of the summarized function
	Want     summaries.FrontendDataflowSummary // Want is the summary being checked
	Got      summaries.DetailedSummary         // Got is the actual summary computed, if any
	GotGraph *dataflow.SummaryGraph            // GotGraph is the actual summary graph computed, if any
	IsSound  bool                              // IsSound is true if Want is an overapproximation of Got
	Time     time.Duration                     // Time is the time spent to calculate the result
}

func (r SoundnessResult) MarshalJSON() ([]byte, error) {
	if r.Want == nil {
		return nil, fmt.Errorf("Want summary is nil for function %s", r.Name)
	}
	b := &bytes.Buffer{}
	raw := rawSoundnessResult{
		Name:        r.Name,
		Want:        rawFlows(r.Want.Summary().Flows),
		Got:         rawFlows(r.Got.Flows),
		IsSound:     r.IsSound,
		TimeSeconds: time.Duration(r.Time.Seconds()),
	}
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false) // don't escape characters like "<"
	err := enc.Encode(raw)
	res := b.Bytes()
	return res, err
}

type rawSoundnessResult struct {
	Name        string
	Want        map[string][]string
	Got         map[string][]string
	IsSound     bool
	TimeSeconds time.Duration
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
