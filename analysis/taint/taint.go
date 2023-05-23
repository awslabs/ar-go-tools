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

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/dataflow"
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

	// ** Second step **
	// The intra-procedural analysis is run on every function `f` such that `ignoreInFirstPass(f)` is
	// false. A dummy summary is inserted for every function that is not analyzed. If that dummy summary is needed
	// later in the inter-procedural analysis, then we [TODO: what do we do?].
	// The goal of this step is to build function summaries: a graph that represents how data flows through the
	// function being analyzed.

	// Only build summaries for non-stdlib functions here
	analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
		AnalyzerState:       state,
		NumRoutines:         numRoutines,
		ShouldCreateSummary: dataflow.ShouldCreateSummary,
		ShouldBuildSummary:  dataflow.ShouldBuildSummary,
		IsEntrypoint:        IsSourceNode,
	})

	// ** Third step **
	// the inter-procedural analysis is run over the entire program, which has been summarized in the
	// previous step by building function summaries. This analysis consists in checking whether there exists a sink
	// that is reachable from a source.
	visitor := NewVisitor(nil)
	analysis.RunCrossFunction(analysis.RunCrossFunctionArgs{
		AnalyzerState: state,
		Visitor:       visitor,
		IsEntrypoint:  dataflow.IsSourceFunction,
	})

	return AnalysisResult{Graph: *state.FlowGraph, TaintFlows: visitor.taints}, nil
}
