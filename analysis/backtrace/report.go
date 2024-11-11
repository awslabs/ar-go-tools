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

// A FlowReport contains the information we serialize about a taint flow: a tag, the source and the sink, and
// the trace from source to sink.
type FlowReport struct {
	Tag   string
	Entry dataflow.ReportNodeInfo
	Trace []dataflow.ReportNodeInfo
}

// report generates a json report for a specific data flow
func report(s *dataflow.AnalyzerState,
	entry dataflow.GraphNode,
	trace Trace,
	ss *config.SlicingSpec) FlowReport {
	entryNode := dataflow.GetReportNodeInfo(dataflow.NodeWithTrace{Node: entry}, s)

	reportTrace := funcutil.Map(trace,
		func(x TraceNode) dataflow.ReportNodeInfo {
			return dataflow.GetReportNodeInfo(dataflow.NodeWithTrace{Node: x.GraphNode}, s)
		})

	return FlowReport{
		Tag:   ss.Tag,
		Entry: entryNode,
		Trace: reportTrace,
	}
}
