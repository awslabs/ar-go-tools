package main

import (
	"github.com/awslabs/argot/analysis/dataflow"
	"golang.org/x/term"
)

// cmdBuildGraph builds the cross-function flow graph given the current summaries
func cmdBuildGraph(tt *term.Terminal, c *dataflow.Cache, _ Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : build the cross-function flow graph.\n",
			tt.Escape.Blue, cmdBuildGraphName, tt.Escape.Reset)
		writeFmt(tt, "\t   Summaries must be built first with `%s%s%s`.\n",
			tt.Escape.Yellow, cmdSummarizeName, tt.Escape.Reset)
		return false
	}
	if len(c.FlowGraph.Summaries) == 0 {
		WriteErr(tt, "No summaries present. Did you run `summarize`?")
		return false
	}
	c.FlowGraph.BuildGraph()
	WriteSuccess(tt, "Built cross function flow graph.")
	return false
}
