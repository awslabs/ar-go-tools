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

// Package analysis contains helper functions for running analysis passes.
package analysis

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// SingleFunctionResult represents the result of running a single-function analysis pass.
type SingleFunctionResult struct {
	FlowGraph dataflow.CrossFunctionFlowGraph
}

// RunSingleFunctionArgs represents the arguments for RunSingleFunction.
type RunSingleFunctionArgs struct {
	AnalyzerState *dataflow.AnalyzerState
	NumRoutines   int

	// ShouldCreateSummary indicates whether a summary object should be created. This does *not* means a summary
	// will be built!
	ShouldCreateSummary func(*ssa.Function) bool

	// ShouldBuildSummary indicates whether the summary should be built when it is created
	ShouldBuildSummary func(*dataflow.AnalyzerState, *ssa.Function) bool

	// IsEntrypoint is a function that returns true if the node should be an entrypoint to the analysis.
	// The entrypoint node is treated as a "source" of data.
	IsEntrypoint func(*config.Config, ssa.Node) bool

	// PostBlockCallback will be called each time a block is analyzed if the analysis is running on a single core
	// This is useful for debugging purposes
	PostBlockCallback func(state *dataflow.IntraAnalysisState)
}

// RunSingleFunction runs a single-function analysis pass of program prog in parallel using numRoutines.
// It builds the function summary if shouldBuildSummary evaluates to true.
// isSourceNode and isSinkNode are configure which nodes should be treated as data flow sources/sinks.
func RunSingleFunction(args RunSingleFunctionArgs) SingleFunctionResult {
	logger := args.AnalyzerState.Logger
	logger.Infof("Starting intra-prpocedural analysis ...")
	start := time.Now()

	fg := dataflow.NewCrossFunctionFlowGraph(map[*ssa.Function]*dataflow.SummaryGraph{}, args.AnalyzerState)
	numRoutines := args.NumRoutines + 1
	if numRoutines < 1 {
		numRoutines = 1
	}

	jobs := []singleFunctionJob{}
	for function := range args.AnalyzerState.ReachableFunctions(false, false) {
		if args.ShouldCreateSummary(function) {
			jobs = append(jobs, singleFunctionJob{
				function:           function,
				analyzerState:      args.AnalyzerState,
				shouldBuildSummary: args.ShouldBuildSummary(args.AnalyzerState, function),
			})
		}
	}

	// Start the single function summary building routines
	results := runJobs(jobs, numRoutines, args.IsEntrypoint)
	collectResults(results, &fg, args.AnalyzerState)

	logger.Infof("Single-function pass done (%.2f s).", time.Since(start).Seconds())

	args.AnalyzerState.FlowGraph = &fg
	return SingleFunctionResult{FlowGraph: fg}
}

// runJobs runs the single-function analysis on each job in jobs in parallel and returns a slice with all the results.
func runJobs(jobs []singleFunctionJob, numRoutines int,
	isEntrypoint func(*config.Config, ssa.Node) bool) []dataflow.SingleFunctionResult {
	f := func(job singleFunctionJob) dataflow.SingleFunctionResult {
		return runSingleFunctionJob(job, isEntrypoint)
	}

	return funcutil.MapParallel(jobs, f, numRoutines)
}

// RunCrossFunctionArgs represents the arguments to RunCrossFunction.
type RunCrossFunctionArgs struct {
	AnalyzerState *dataflow.AnalyzerState
	Visitor       dataflow.Visitor
	IsEntrypoint  func(*config.Config, ssa.Node) bool
}

// RunCrossFunction runs the cross-function analysis pass.
// It builds args.FlowGraph and populates args.DataFlowCandidates based on additional data from the analysis.
func RunCrossFunction(args RunCrossFunctionArgs) {
	args.AnalyzerState.Logger.Infof("Starting inter-procedural pass...")
	start := time.Now()
	args.AnalyzerState.FlowGraph.CrossFunctionPass(args.AnalyzerState, args.Visitor, args.IsEntrypoint)
	args.AnalyzerState.Logger.Infof("Cross-function pass done (%.2f s).", time.Since(start).Seconds())
}

// singleFunctionJob contains all the information necessary to run the single-function analysis on function.
type singleFunctionJob struct {
	analyzerState      *dataflow.AnalyzerState
	function           *ssa.Function
	shouldBuildSummary bool
	postBlockCallback  func(*dataflow.IntraAnalysisState)
	output             chan *dataflow.SummaryGraph
}

// runSingleFunctionJob runs the single-function analysis with the information in job
// and returns the result of the analysis.
func runSingleFunctionJob(job singleFunctionJob,
	isEntrypoint func(*config.Config, ssa.Node) bool) dataflow.SingleFunctionResult {
	job.analyzerState.Logger.Infof("Analyzing Pkg: %s | Func: %s ...",
		lang.PackageNameFromFunction(job.function), job.function.Name())
	result, err := dataflow.SingleFunctionAnalysis(job.analyzerState, job.function,
		job.shouldBuildSummary, dataflow.GetUniqueFunctionId(), isEntrypoint, job.postBlockCallback)

	if err != nil {
		job.analyzerState.Logger.Errorf("error while analyzing %s:\n\t%v\n", job.function.Name(), err)
		return dataflow.SingleFunctionResult{}
	}

	job.analyzerState.Logger.Debugf("Pkg: %-60s | Func: %-30s | %-5t | %.2f s\n",
		lang.PackageNameFromFunction(job.function), job.function.Name(), job.shouldBuildSummary,
		result.Time.Seconds())

	summary := result.Summary
	if summary != nil {
		summary.ShowAndClearErrors(job.analyzerState.Logger.GetError().Writer())
	}

	return dataflow.SingleFunctionResult{Summary: summary, Time: result.Time}
}

// collectResults waits for the results in c and adds them to graph, candidates. It waits for numProducers
// messages on the done channel to terminate and clean up.
// Operations on graph and candidates are sequential.
// cleans up done and c channels
func collectResults(c []dataflow.SingleFunctionResult, graph *dataflow.CrossFunctionFlowGraph,
	state *dataflow.AnalyzerState) {
	var f *os.File
	var err error
	if state.Config.ReportSummaries {
		f, err = os.CreateTemp(state.Config.ReportsDir, "summary-times-*.csv")
		if err != nil {
			state.Logger.Errorf("Could not create summary times report file.")
		}
		defer f.Close()
		path, err := filepath.Abs(f.Name())
		if err != nil {
			state.Logger.Errorf("Could not find absolute path of summary times report file %s.", f.Name())
		}
		state.Logger.Infof("Saving report of summary times in %s\n", path)
	}

	for _, result := range c {
		if result.Summary != nil {
			graph.Summaries[result.Summary.Parent] = result.Summary
			if f != nil {
				// should be race-free because it's only run in one goroutine
				reportSummaryTime(f, result)
			}
		}
	}
}

func reportSummaryTime(w io.Writer, result dataflow.SingleFunctionResult) {
	str := fmt.Sprintf("%s, %.2f\n", result.Summary.Parent.String(), result.Time.Seconds())
	w.Write([]byte(str))
}
