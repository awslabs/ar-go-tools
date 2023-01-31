package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/format"
	"io"
	"os"
	"sort"
	"strings"
)

// addCoverage adds an entry to coverage by properly formatting the position of the visitorNode in the context of
// the cache
func addCoverage(c *dataflow.Cache, elt visitorNode, coverage map[string]bool) {
	pos := elt.Node.Position(c)
	if coverage != nil {
		if strings.Contains(pos.Filename, c.Config.Coverage) {
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

// ReportTaintFlow reports a taint flow by writing to a file if the configuration has the ReportPaths flag set,
// and writing in the logger
func ReportTaintFlow(c *dataflow.Cache, source dataflow.NodeWithTrace, sink dataflow.NodeWithTrace) {
	c.Logger.Printf(" 💀 Sink reached at %s\n", format.Red(sink.Node.Position(c)))
	c.Logger.Printf(" Add new path from %s to %s <== \n",
		format.Green(source.Node.String()), format.Red(sink.Node.String()))
	if c.Config.ReportPaths {
		tmp, err := os.CreateTemp(c.Config.ReportsDir, "flow-*.out")
		if err != nil {
			c.Logger.Printf("Could not write report.")
		}
		defer tmp.Close()
		c.Logger.Printf("Report in %s\n", tmp.Name())

		tmp.WriteString(fmt.Sprintf("Source: %s\n", source.Node.String()))
		tmp.WriteString(fmt.Sprintf("At: %s\n", source.Node.Position(c)))
		tmp.WriteString(fmt.Sprintf("Sink: %s\n", sink.Node.String()))
		tmp.WriteString(fmt.Sprintf("At: %s\n", sink.Node.Position(c)))
	}
}
