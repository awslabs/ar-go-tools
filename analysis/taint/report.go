package taint

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/format"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/packagescan"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
)

// addCoverage adds an entry to coverage by properly formatting the position of the visitorNode in the context of
// the cache
func addCoverage(c *dataflow.Cache, elt *visitorNode, coverage map[string]bool) {
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
func ReportTaintFlow(c *dataflow.Cache, source dataflow.NodeWithTrace, sink *visitorNode) {
	c.Logger.Printf(" 💀 Sink reached at %s\n", format.Red(sink.Node.Position(c)))
	c.Logger.Printf(" Add new path from %s to %s <== \n",
		format.Green(source.Node.String()), format.Red(sink.Node.String()))
	sinkPos := sink.Node.Position(c)
	if callArg, isCallArgsink := sink.Node.(*dataflow.CallNodeArg); isCallArgsink {
		sinkPos = callArg.ParentNode().Position(c)
	}
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
		tmp.WriteString(fmt.Sprintf("At: %s\n", sinkPos))

		nodes := []*visitorNode{}
		cur := sink
		for cur != nil {
			nodes = append(nodes, cur)
			cur = cur.prev
		}

		tmp.WriteString(fmt.Sprintf("Trace:\n"))
		prefix := c.Logger.Prefix()
		c.Logger.SetPrefix(prefix + "TRACE: ")
		for i := len(nodes) - 1; i >= 0; i-- {
			tmp.WriteString(fmt.Sprintf("%s\n", nodes[i].Node.Position(c).String()))
			c.Logger.Printf("[%s] %s\n", dataflow.FuncNames(nodes[i].Trace), nodes[i].Node.Position(c).String())
		}
		c.Logger.Printf("SINK: %s\n", sinkPos.String())
		c.Logger.SetPrefix(prefix)
	}
}

func printMissingSummaryMessage(c *dataflow.Cache, callSite *dataflow.CallNode) {
	if !c.Config.Verbose {
		return
	}

	var typeString string
	if callSite.Callee() == nil {
		typeString = fmt.Sprintf("nil callee (in %s)",
			packagescan.SafeFunctionPos(callSite.Graph().Parent).ValueOr(packagescan.DummyPos))
	} else {
		typeString = callSite.Callee().Type().String()
	}
	c.Logger.Printf(format.Red(fmt.Sprintf("| %s has not been summarized (call %s).",
		callSite.String(), typeString)))
	if callSite.Callee() != nil && callSite.CallSite() != nil {
		c.Logger.Printf(fmt.Sprintf("| Please add %s to summaries", callSite.Callee().String()))

		pos := callSite.Position(c)
		if pos != packagescan.DummyPos {
			c.Logger.Printf("|_ See call site: %s", pos)
		} else {
			opos := packagescan.SafeFunctionPos(callSite.Graph().Parent)
			c.Logger.Printf("|_ See call site in %s", opos.ValueOr(packagescan.DummyPos))
		}

		methodFunc := callSite.CallSite().Common().Method
		if methodFunc != nil {
			methodKey := callSite.CallSite().Common().Value.Type().String() + "." + methodFunc.Name()
			c.Logger.Printf("| Or add %s to dataflow contracts", methodKey)
		}
	}
}

func printMissingClosureSummaryMessage(c *dataflow.Cache, closureNode *dataflow.ClosureNode) {
	if !c.Config.Verbose {
		return
	}

	var instrStr string
	if closureNode.Instr() == nil {
		instrStr = "nil instr"
	} else {
		instrStr = closureNode.Instr().String()
	}
	c.Logger.Printf(format.Red(fmt.Sprintf("| %s has not been summarized (closure %s).",
		closureNode.String(), instrStr)))
	if closureNode.Instr() != nil {
		c.Logger.Printf("| Please add closure %s to summaries",
			closureNode.Instr().Fn.String())
		c.Logger.Printf("|_ See closure: %s", closureNode.Position(c))
	}
}

func printWarningSummaryNotConstructed(c *dataflow.Cache, callSite *dataflow.CallNode) {
	if !c.Config.Verbose {
		return
	}

	c.Logger.Printf("| %s: summary has not been built for %s.",
		format.Yellow("WARNING"),
		format.Yellow(callSite.Graph().Parent.Name()))
	pos := callSite.Position(c)
	if pos != packagescan.DummyPos {
		c.Logger.Printf(fmt.Sprintf("|_ See call site: %s", pos))
	} else {
		opos := packagescan.SafeFunctionPos(callSite.Graph().Parent)
		c.Logger.Printf(fmt.Sprintf("|_ See call site in %s", opos.ValueOr(packagescan.DummyPos)))
	}

	if callSite.CallSite() != nil {
		methodKey := ssafuncs.InstrMethodKey(callSite.CallSite())
		if methodKey.IsSome() {
			c.Logger.Printf(fmt.Sprintf("| Or add %s to dataflow contracts", methodKey.ValueOr("?")))
		}
	}
}
