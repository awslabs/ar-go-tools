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
	"log"
	"runtime"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/escape"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

type AnalysisResult struct {
	// TaintFlows contains all the data flows from the sources to the sinks detected during the analysis
	TaintFlows TaintFlows

	// Graph is the cross function dataflow graph built by the dataflow analysis. It contains the linked summaries of
	// each function appearing in the program and analyzed.
	Graph dataflow.CrossFunctionFlowGraph

	// Errors contains a list of errors produced by the analysis. Errors may have been added at different steps of the
	// analysis.
	Errors []error
}

// Analyze runs the taint analysis on the program prog with the user-provided configuration config.
// If the analysis run successfully, a FlowInformation is returned, containing all the information collected.
// FlowInformation.SinkSources will map all the sinks encountered to the set of sources that reach them.
//
// - cfg is the configuration that determines which functions are sources, sinks and sanitizers.
//
// - prog is the built ssa representation of the program. The program must contain a main package and include all its
// dependencies, otherwise the pointer analysis will fail.
func Analyze(logger *log.Logger, cfg *config.Config, prog *ssa.Program) (AnalysisResult, error) {
	// Number of working routines to use in parallel. TODO: make this an option?
	numRoutines := runtime.NumCPU() - 1
	if numRoutines <= 0 {
		numRoutines = 1
	}

	// ** First step **
	// - Running the pointer analysis over the whole program. We will query values only in
	// the user defined functions since we plan to analyze only user-defined functions. Any function from the runtime
	// or from the standard library that is called in the program should be summarized in the summaries package.
	// - Running the type analysis to map functions to their type

	state, err := dataflow.NewInitializedAnalyzerState(logger, cfg, prog)
	if err != nil {
		return AnalysisResult{}, err
	}

	// Optional step: running the escape analysis
	if cfg.UseEscapeAnalysis {
		escape.InitializeEscapeAnalysisState(state)
	}

	// ** Second step **
	// The intra-procedural analysis is run on every function `f` such that `ignoreInFirstPass(f)` is
	// false. A dummy summary is inserted for every function that is not analyzed. If that dummy summary is needed
	// later in the inter-procedural analysis, then we [TODO: what do we do?].
	// The goal of this step is to build function summaries: a graph that represents how data flows through the
	// function being analyzed.

	if cfg.SummarizeOnDemand {
		singleFunctionSummarizeOnDemand(state, cfg, numRoutines)
	} else {
		// Only build summaries for non-stdlib functions here
		analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
			AnalyzerState:       state,
			NumRoutines:         numRoutines,
			ShouldCreateSummary: dataflow.ShouldCreateSummary,
			ShouldBuildSummary:  dataflow.ShouldBuildSummary,
			IsEntrypoint:        IsSourceNode,
		})
	}

	// ** Third step **
	// the inter-procedural analysis is run over the entire program, which has been summarized in the
	// previous step by building function summaries. This analysis consists in checking whether there exists a sink
	// that is reachable from a source.
	visitor := NewVisitor(nil)
	analysis.RunCrossFunction(analysis.RunCrossFunctionArgs{
		AnalyzerState: state,
		Visitor:       visitor,
		IsEntrypoint: func(c *config.Config, node ssa.Node) bool {
			if f, ok := node.(*ssa.Function); ok {
				return dataflow.IsSourceFunction(c, f)
			}

			if c.SummarizeOnDemand {
				return IsSourceNode(c, node)
			}

			return false
		},
	})

	return AnalysisResult{Graph: *state.FlowGraph, TaintFlows: visitor.taints}, nil
}

func singleFunctionSummarizeOnDemand(state *dataflow.AnalyzerState, cfg *config.Config, numRoutines int) {
	sourceFuncs := []*ssa.Function{}
	for f := range dataflow.CallGraphReachable(state.PointerAnalysis.CallGraph, false, false) {
		pkg := ""
		if f.Package() != nil {
			pkg = f.Package().String()
		}
		if cfg.IsSource(config.CodeIdentifier{
			Package:  pkg,
			Method:   f.Name(),
			Receiver: "",
			Field:    "",
			Type:     "",
			Label:    "",
		}) {
			sourceFuncs = append(sourceFuncs, f)
		}

		for _, blk := range f.Blocks {
			for _, instr := range blk.Instrs {
				var fieldName string
				if field, ok := instr.(*ssa.Field); ok {
					fieldName = dataflow.FieldFieldName(field)
				} else if fieldAddr, ok := instr.(*ssa.FieldAddr); ok {
					fieldName = dataflow.FieldAddrFieldName(fieldAddr)
				}
				if fieldName != "" && cfg.IsSource(config.CodeIdentifier{
					Package:  pkg,
					Method:   "",
					Receiver: "",
					Field:    fieldName,
					Type:     "",
					Label:    "",
				}) {
					sourceFuncs = append(sourceFuncs, f)
				}
			}
		}
	}

	// shouldSummarize stores all the functions that should be summarized
	shouldSummarize := map[*ssa.Function]bool{}
	for _, source := range sourceFuncs {
		callers := allCallers(state, source)
		for _, c := range callers {
			if dataflow.ShouldBuildSummary(state, c.Caller.Func) {
				shouldSummarize[c.Caller.Func] = true
			}
		}
	}

	analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
		AnalyzerState: state,
		NumRoutines:   numRoutines,
		ShouldCreateSummary: func(f *ssa.Function) bool {
			return shouldSummarize[f]
		},
		ShouldBuildSummary: func(_ *dataflow.AnalyzerState, f *ssa.Function) bool {
			return shouldSummarize[f]
		},
		IsEntrypoint: func(c *config.Config, n ssa.Node) bool {
			return IsSourceNode(c, n)
		},
	})
}

func allCallers(state *dataflow.AnalyzerState, entry *ssa.Function) []*callgraph.Edge {
	node := state.PointerAnalysis.CallGraph.Nodes[entry]
	res := make([]*callgraph.Edge, 0, len(node.In))
	for _, in := range node.In {
		if in.Caller != nil {
			res = append(res, in)
		}
	}

	return res
}
