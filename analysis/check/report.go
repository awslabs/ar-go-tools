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
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
)

// SoundnessResult is the result of checking the soundness of a single data flow summary.
type SoundnessResult struct {
	Name     string                            // Name is the name of the summarized function
	Want     summaries.FrontendDataflowSummary // Want is the summary being checked
	Got      summaries.DetailedSummary         // Got is the actual summary computed, if any
	GotGraph *dataflow.SummaryGraph            // GotGraph is the actual summary graph computed, if any
	IsSound  bool                              // IsSound is true if Want is an overapproximation
}
