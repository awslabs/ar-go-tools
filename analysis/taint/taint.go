// Package taint contains all the taint analysis functionality in argot. The Analyze function is the main entry
// point of the analysis, and callees the singleFunctionAnalysis and crossFunction analysis functions in two distinct
// whole-program analysis steps.
package taint

import (
	"log"
	"runtime"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/summaries"
	"golang.org/x/tools/go/ssa"
)

type AnalysisResult struct {
	// TaintFlows contains all the data flows from the sources to the sinks detected during the analysis
	TaintFlows dataflow.DataFlows

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

	prog.Build()
	cache, err := dataflow.NewCache(prog, logger, cfg, []func(*dataflow.Cache){
		func(cache *dataflow.Cache) { cache.PopulateTypesVerbose() },
		func(cache *dataflow.Cache) { cache.PopulatePointersVerbose(summaries.IsUserDefinedFunction) },
		func(cache *dataflow.Cache) { cache.PopulateGlobalsVerbose() },
	})
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
	res := analysis.RunSingleFunction(analysis.RunSingleFunctionArgs{
		Cache:               cache,
		NumRoutines:         numRoutines,
		ShouldCreateSummary: ShouldCreateSummary,
		IsSourceNode:        IsSourceNode,
		IsSinkNode:          IsSinkNode,
	})
	flowCandidates := res.FlowCandidates
	fg := res.FlowGraph

	// ** Third step **
	// the inter-procedural analysis is run over the entire program, which has been summarized in the
	// previous step by building function summaries. This analysis consists in checking whether there exists a sink
	// that is reachable from a source.
	analysis.RunCrossFunction(analysis.RunCrossFunctionArgs{
		Cache:              cache,
		FlowGraph:          fg,
		DataFlowCandidates: flowCandidates,
		Visitor:            VisitFromSource,
	})

	return AnalysisResult{TaintFlows: flowCandidates, Graph: fg}, nil
}

func ShouldCreateSummary(f *ssa.Function) bool {
	return (!summaries.IsStdFunction(f) && summaries.IsUserDefinedFunction(f)) || summaries.IsSummaryRequired(f)
}
