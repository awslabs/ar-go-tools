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
	"github.com/awslabs/ar-go-tools/internal/formatutil"
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
	traces map[dataflow.NodeWithTrace][]Trace,
	ss config.SlicingSpec) FlowReports {
	traceMap := make(map[string][][]dataflow.ReportNodeInfo)
	for entryPt, tracesFromEntryPt := range traces {
		reportTraces :=
			funcutil.Map(tracesFromEntryPt, func(trace Trace) []dataflow.ReportNodeInfo {
				return funcutil.Map(trace,
					func(x *dataflow.VisitorNode) dataflow.ReportNodeInfo {
						return dataflow.GetReportNodeInfo(x.NodeWithTrace, s)
					})
			})
		traceMap[entryPt.Node.String()] = reportTraces
	}

	return FlowReports{
		Tag:    ss.Tag,
		Traces: traceMap,
	}
}

// logTraces logs resTraces using the state's logger.
func logTraces(s *dataflow.State, resTraces map[dataflow.NodeWithTrace][]Trace) {
	for entry, traces := range resTraces {
		s.Logger.Infof("Found %d data flow(s) from backtrace-point: %v\n",
			len(traces), dataflow.TermNodeSummary(entry.Node))
		// - Context [<calling context string>] Pos: <position in source code>
		s.Logger.Infof("%s - Context [%s]\n",
			" |",
			dataflow.FuncNames(entry.Trace, s.Logger.LogsDebug()))
		s.Logger.Infof("%s - %s %s\n",
			" |",
			formatutil.Yellow("At"),
			entry.Node.Position(s).String())
		for _, trace := range traces {
			logTrace(s, trace)
		}
	}
}

// logTrace logs the trace using the state's logger.
func logTrace(s *dataflow.State, trace Trace) {
	if len(trace) == 0 {
		return
	}

	first := trace[0]
	last := trace[len(trace)-1]
	s.Logger.Infof(" Flow:")
	s.Logger.Infof("  |- Data at %s (%s)", last.Node.Position(s), formatutil.Green(last.Node.String()))
	s.Logger.Infof("  |- Originates from data at %s (%s)\n", first.Node.Position(s), formatutil.Red(first.Node.String()))

	if s.Config.ReportPaths {
		for _, node := range trace {
			s.Logger.Infof("%s - %s",
				formatutil.Blue("  |- TRACE"),
				dataflow.TermNodeSummary(node.Node))
			// - Context [<calling context string>] Pos: <position in source code>
			s.Logger.Infof("%s - Context [%s]\n",
				"  |  ",
				dataflow.FuncNames(node.Trace, s.Logger.LogsDebug()))
			s.Logger.Infof("%s - %s %s\n",
				"  |  ",
				formatutil.Yellow("At"),
				node.Node.Position(s).String())
		}
		s.Logger.Infof("")
	}
}
