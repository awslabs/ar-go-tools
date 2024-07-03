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

package taint

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// traceNodes prints trace information about the cur node.
func traceNode(s *dataflow.AnalyzerState, cur *dataflow.VisitorNode) {
	if !s.Logger.LogsTrace() {
		return
	}
	s.Logger.Tracef("(s=%v) Visiting %T node: %v\n\tat %v\n",
		cur.Status.Kind, cur.Node, cur.Node, cur.Node.Position(s))
	s.Logger.Tracef("Trace: %s\n", cur.Trace.String())
}

// panicOnUnexpectedMissingFreeVar **panics**, but adds and error to the state before.
func panicOnUnexpectedMissingFreeVar(s *dataflow.AnalyzerState,
	makeClosureSite *dataflow.ClosureNode, graphNode *dataflow.FreeVarNode) {
	s.AddError(
		fmt.Sprintf("no bound variable matching free variable in %s",
			makeClosureSite.ClosureSummary.Parent.String()),
		fmt.Errorf("at position %d", graphNode.Index()))
	panic(
		fmt.Errorf(
			"[No Context] no bound variable matching free variable in %s at position %d",
			makeClosureSite.ClosureSummary.Parent.String(), graphNode.Index()))
}

// addCoverage adds an entry to coverage by properly formatting the position of the visitorNode in the context of
// the analyzer state
func addCoverage(c *dataflow.AnalyzerState, elt *dataflow.VisitorNode, coverage map[string]bool) {
	pos := elt.Node.Position(c)
	if coverage != nil {
		if c.Config.MatchCoverageFilter(pos.Filename) {
			s := fmt.Sprintf("%s:%d.1,%d.%d 1 1\n", pos.Filename, pos.Line, pos.Line, pos.Column)
			coverage[s] = true
		}
	}
}

// reportCoverage writes the coverage data contains in the coverage map to the coverageWriter
// The strings in the coverage map are sorted and then written to the coverage writer
func reportCoverage(coverage map[string]bool, coverageWriter io.StringWriter) {
	if coverageWriter != nil {
		var cov []string
		for covered := range coverage {
			cov = append(cov, covered)
		}
		sort.Slice(cov, func(i int, j int) bool { return cov[i] < cov[j] })

		for _, line := range cov {
			coverageWriter.WriteString(line)
		}
	}
}

// reportTaintFlow reports a taint flow by writing to a file if the configuration has the ReportPaths flag set,
// and writing in the logger
func reportTaintFlow(c *dataflow.AnalyzerState, source dataflow.NodeWithTrace, sink *dataflow.VisitorNode) {
	c.Logger.Infof(" 💀 Sink reached at %s\n", formatutil.Red(sink.Node.Position(c)))
	c.Logger.Infof(" Add new path from %s to %s <== \n",
		formatutil.Green(source.Node.String()), formatutil.Red(sink.Node.String()))
	sinkPos := sink.Node.Position(c)
	if callArg, isCallArgsink := sink.Node.(*dataflow.CallNodeArg); isCallArgsink {
		sinkPos = callArg.ParentNode().Position(c)
	}
	if c.Config.ReportPaths {
		tmp, err := os.CreateTemp(c.Config.ReportsDir, "flow-*.out")
		if err != nil {
			c.Logger.Errorf("Could not write report.")
		}
		defer tmp.Close()
		c.Logger.Infof("Report in %s\n", tmp.Name())

		tmp.WriteString(fmt.Sprintf("Source: %s\n", source.Node.String()))
		tmp.WriteString(fmt.Sprintf("At: %s\n", source.Node.Position(c)))
		tmp.WriteString(fmt.Sprintf("Sink: %s\n", sink.Node.String()))
		tmp.WriteString(fmt.Sprintf("At: %s\n", sinkPos))

		nodes := []*dataflow.VisitorNode{}
		cur := sink
		for cur != nil {
			nodes = append(nodes, cur)
			cur = cur.Prev
		}

		tmp.WriteString(fmt.Sprintf("Trace:\n"))
		for i := len(nodes) - 1; i >= 0; i-- {
			if nodes[i].Status.Kind != dataflow.DefaultTracing {
				continue
			}
			tmp.WriteString(fmt.Sprintf("%s\n", nodes[i].Node.Position(c).String()))
			c.Logger.Infof("%s - %s",
				formatutil.Purple("TRACE"),
				dataflow.NodeSummary(nodes[i].Node))
			// - Context [<calling context string>] Pos: <position in source code>
			c.Logger.Infof("%s - Context [%s] %s %s\n",
				"     ",
				dataflow.FuncNames(nodes[i].Trace),
				formatutil.Yellow("Pos:"),
				nodes[i].Node.Position(c).String())
		}
		c.Logger.Infof("-- ENDS WITH SINK: %s\n", sinkPos.String())
	}
}
