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
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// A FlowReports contains the information we serialize about backwards data flow traces. Traces are grouped by problem
// tag. A trace in the report is a list of dataflow.ReportNodeInfo.
type FlowReports struct {
	Tag    string
	Traces map[string][][]dataflow.ReportNodeInfo
}

// report generates a json report for a specific data flow
func report(s *dataflow.State,
	traces map[dataflow.GraphNode][]Trace,
	ss *config.SlicingSpec) FlowReports {
	traceMap := make(map[string][][]dataflow.ReportNodeInfo)
	for entryPt, tracesFromEntryPt := range traces {
		reportTraces :=
			funcutil.Map(tracesFromEntryPt, func(trace Trace) []dataflow.ReportNodeInfo {
				return funcutil.Map(trace,
					func(x TraceNode) dataflow.ReportNodeInfo {
						return dataflow.GetReportNodeInfo(dataflow.NodeWithTrace{Node: x.GraphNode}, s)
					})
			})
		traceMap[entryPt.String()] = reportTraces
	}

	return FlowReports{
		Tag:    ss.Tag,
		Traces: traceMap,
	}
}
