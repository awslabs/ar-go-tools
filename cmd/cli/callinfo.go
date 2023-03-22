package main

import (
	"regexp"

	"github.com/awslabs/argot/analysis/dataflow"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
)

// cmdCallers shows the callers of a given summarized function
func cmdCallers(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: shows the callers of a given summarized function.\n",
			tt.Escape.Blue, cmdCallersName, tt.Escape.Reset)
		writeFmt(tt, "\t    %s will only be accurate after `%s%s%s`.\n",
			cmdCallersName, tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		return false
	}

	return displayCallInfo(tt, c, command, false, true)
}

// cmdCallees shows the callers of a given summarized function
func cmdCallees(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s: shows the callees of a given summarized function.\n",
			tt.Escape.Blue, cmdCalleesName, tt.Escape.Reset)
		writeFmt(tt, "\t    %s will only be accurate after `%s%s%s`.\n",
			cmdCalleesName, tt.Escape.Yellow, cmdBuildGraphName, tt.Escape.Reset)
		return false
	}
	return displayCallInfo(tt, c, command, true, false)
}

// displayCallInfo displays callers or/and callee information for a specific command.
// If displayCallees is true, displays the callees for each function matching the commands' argument
// If displayCaller is true, displays the callers for each function matching the commands' argument
//
// If the matching function has a summary, then the summary's info is used.
// Otherwise, the info contained in the pointer analysis' result is used.
func displayCallInfo(tt *term.Terminal, c *dataflow.Cache, command Command,
	displayCallees bool, displayCallers bool) bool {
	targetFilter := func(f *ssa.Function) bool { return f != nil }

	if filterArg, hasArg := command.NamedArgs["filter"]; hasArg {
		filterRegex, err := regexp.Compile(filterArg)
		if err != nil {
			regexErr(tt, filterArg, err)
			return false
		}
		targetFilter = func(f *ssa.Function) bool {
			if f == nil {
				return false
			}
			return filterRegex.MatchString(f.String())
		}
	}

	for _, f := range funcsMatchingCommand(tt, c, command) {
		// Strategy 1: the function has a summary, use it to determine callees
		// the information in a summary should be more complete than callgraph, if the callgraph sometimes
		// omits static calls
		if summary, hasSummary := c.FlowGraph.Summaries[f]; hasSummary {
			if displayCallees {
				WriteSuccess(tt, "All functions called by %s:", f.String())
				for instr, callees := range summary.Callees {
					writeFmt(tt, "\tAt SSA instruction %s:\n", instr.String())
					for callee, node := range callees {
						if targetFilter(callee) {
							writeFmt(tt, "\t  %s\n", callee.String())
							writeFmt(tt, "\t  position: %s\n", node.Position(c).String())
						}
					}
				}
			}
			if displayCallers {
				WriteSuccess(tt, "Callers of %s:", f.String())
				for _, callsite := range summary.Callsites {
					if targetFilter(callsite.Callee()) {
						writeFmt(tt, "\tAt SSA instruction %s\n", callsite.String())
						if callsite.Graph() != nil {
							writeFmt(tt, "\t  in %s\n", callsite.Graph().Parent.Name())
						}
						writeFmt(tt, "\t  position: %s\n", callsite.Position(c).String())
					}
				}
			}
		} else {
			// If there is no summary, then use the callgraph computed during the pointer analysis
			// the cache should always contain the pointer analysis, and it should not be null
			if node, ok := c.PointerAnalysis.CallGraph.Nodes[f]; ok {
				if displayCallees {
					WriteSuccess(tt, "All functions called by %s:", f.String())
					for _, out := range node.Out {
						if out.Callee != nil && targetFilter(out.Callee.Func) {
							if out.Site != nil {
								writeFmt(tt, "\tAt SSA instruction %s:\n", out.Site.String())
								writeFmt(tt, "\t - position: %s\n", c.Program.Fset.Position(out.Site.Pos()))
							}
							writeFmt(tt, "\t - %s\n", out.Callee.Func.String())
						}
					}
				}
				if displayCallers {
					WriteSuccess(tt, "Callers of %s:", f.String())
					for _, in := range node.In {
						if in.Caller != nil && targetFilter(in.Caller.Func) {
							if in.Site != nil {
								writeFmt(tt, "\tAt SSA instruction %s:\n", in.Site.String())
								writeFmt(tt, "\t - position: %s\n", c.Program.Fset.Position(in.Site.Pos()))
							}
							writeFmt(tt, "\t - %s\n", in.Caller.Func.String())
						}
					}
				}
			}
		}
	}
	return false
}
