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

package cli

import (
	"regexp"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"golang.org/x/tools/go/ssa"
)

// cmdCallers shows the callers of a given summarized function
func cmdCallers(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: shows the callers of a given summarized function.\n",
			o.EscBlue(), CmdCallersName, o.EscReset())
		o.Write("\t    %s will only be accurate after `%s%s%s`.\n",
			CmdCallersName, o.EscYellow(), CmdBuildGraphName, o.EscReset())
		o.Write("\t    -ptr to use pointer analysis callgraph only.\n")
		return false
	}
	usePtr := false
	if command.Flags["ptr"] {
		usePtr = true
	}
	return displayCallInfo(o, sess, command, usePtr, false, true)
}

// cmdCallees shows the callers of a given summarized function
func cmdCallees(o Outputter, sess *Session, command Command, _ bool) bool {
	if sess == nil {
		o.Write("\t- %s%s%s: shows the callees of a given summarized function.\n",
			o.EscBlue(), CmdCalleesName, o.EscReset())
		o.Write("\t    %s will only be accurate after `%s%s%s`.\n",
			CmdCalleesName, o.EscYellow(), CmdBuildGraphName, o.EscReset())
		o.Write("\t    -ptr to use pointer analysis callgraph only.\n")
		return false
	}
	usePtr := false
	if command.Flags["ptr"] {
		usePtr = true
	}
	return displayCallInfo(o, sess, command, usePtr, true, false)
}

// displayCallInfo displays callers or/and callee information for a specific command.
// If displayCallees is true, displays the callees for each function matching the commands' argument
// If displayCaller is true, displays the callers for each function matching the commands' argument
//
// If the matching function has a summary, then the summary's info is used.
// Otherwise, the info contained in the pointer analysis' result is used.
func displayCallInfo(o Outputter, sess *Session, command Command, usePtr bool,
	displayCallees bool, displayCallers bool) bool {
	targetFilter := func(f *ssa.Function) bool { return f != nil }

	if filterArg, hasArg := command.NamedArgs["filter"]; hasArg {
		filterRegex, err := regexp.Compile(filterArg)
		if err != nil {
			regexErr(o, filterArg, err)
			return false
		}
		targetFilter = func(f *ssa.Function) bool {
			if f == nil {
				return false
			}
			return filterRegex.MatchString(f.String())
		}
	}
	funcs, err := sess.funcsMatchingCommand(o, command)
	if err != nil {
		return false
	}
	for _, f := range funcs {
		if summary, hasSummary := sess.hasSummary(f); hasSummary && !usePtr && summary != nil {
			// Strategy 1: the function has a summary, use it to determine callees
			// the information in a summary should be more complete than callgraph, if the callgraph sometimes
			// omits static calls
			dfg, _ := sess.loadDataflowAnalysis().Value() // should not fail since we have summary
			if dfg == nil {
				panic("internal error")
			}
			displayCallInfoWithSummary(dfg, o, f, summary, targetFilter, displayCallers, displayCallees)
		} else {
			// If there is no summary, or usePtr is true, then use the callgraph computed during
			// the pointer analysis  the state should always contain the pointer analysis,
			// and it should not be null
			displayCallInfoWithoutSummary(sess, o, f, targetFilter, displayCallers, displayCallees)
		}
	}
	return false
}

func displayCallInfoWithSummary(s *dataflow.State, o Outputter,
	f *ssa.Function, summary *dataflow.SummaryGraph,
	targetFilter func(*ssa.Function) bool,
	displayCallers bool, displayCallees bool) {
	if summary == nil {
		o.Write("\t No info for nil summary.\n")
	}

	if displayCallees {
		o.WriteSuccess("All functions called by %s:", f.String())
		for instr, callees := range summary.Callees {
			o.Write("\tAt SSA instruction %s:\n", instr.String())
			o.Write("\t Position %s:\n", s.Program.Fset.Position(instr.Pos()))
			for callee := range callees {
				if targetFilter(callee) {
					o.Write("\t  %s\n", callee.String())
					o.Write("\t    position: %s\n", s.Program.Fset.Position(callee.Pos()))
				}
			}
		}
	}
	if displayCallers {
		o.WriteSuccess("Callers of %s:", f.String())
		for _, callsite := range summary.Callsites {
			if targetFilter(callsite.Callee()) {
				o.Write("\tAt SSA instruction %s\n", callsite.String())
				if callsite.Graph() != nil {
					o.Write("\t  in %s\n", callsite.Graph().Parent.Name())
				}
				o.Write("\t  position: %s\n", callsite.Position(s).String())
			}
		}
	}
}

func displayCallInfoWithoutSummary(s *Session, o Outputter,
	f *ssa.Function, targetFilter func(*ssa.Function) bool,
	displayCallers bool, displayCallees bool) {
	if s == nil || f == nil {
		return
	}
	ptrAnalysis, err := s.loadPtrAnalysis().Value()
	if err != nil {
		o.Write("\t%s\n", err)
		return
	}
	if node, ok := ptrAnalysis.PointerAnalysis.CallGraph.Nodes[f]; ok {
		if displayCallees {
			o.WriteSuccess("All functions called by %s:", f.String())
			for _, out := range node.Out {
				if out.Callee != nil && targetFilter(out.Callee.Func) {
					if out.Site != nil {
						o.Write("\tAt SSA instruction %s:\n", out.Site.String())
						o.Write("\t - position: %s\n", ptrAnalysis.Program.Fset.Position(out.Site.Pos()))
					}
					o.Write("\t - %s\n", out.Callee.Func.String())
				}
			}
		}
		if displayCallers {
			o.WriteSuccess("Callers of %s:", f.String())
			for _, in := range node.In {
				if in.Caller != nil && targetFilter(in.Caller.Func) {
					if in.Site != nil {
						o.Write("\tAt SSA instruction %s:\n", in.Site.String())
						o.Write("\t - position: %s\n", ptrAnalysis.Program.Fset.Position(in.Site.Pos()))
					}
					o.Write("\t - %s\n", in.Caller.Func.String())
				}
			}
		}
	}
}
