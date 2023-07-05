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

// IntraAnalysisParams represents the arguments for RunIntraProcedural.
type IntraAnalysisParams struct {
	// ShouldCreateSummary indicates whether a summary object should be created. This does *not* mean a summary
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

// RunIntraProcedural runs an intra-procedural analysis pass of program prog in parallel using numRoutines, using the
// analyzer state. The args specify the intraprocedural analysis parameters.
// RunIntraProcedural updates the summaries stored in the state's FlowGraph
func RunIntraProcedural(state *dataflow.AnalyzerState, numRoutines int, args IntraAnalysisParams) {
	state.Logger.Infof("Starting intra-procedural analysis ...")
	start := time.Now()

	fg := dataflow.NewInterProceduralFlowGraph(map[*ssa.Function]*dataflow.SummaryGraph{}, state)
	numRoutines = numRoutines + 1
	if numRoutines < 1 {
		numRoutines = 1
	}

	var jobs []singleFunctionJob
	for function := range state.ReachableFunctions(false, false) {
		if args.ShouldCreateSummary(function) {
			jobs = append(jobs, singleFunctionJob{
				function:           function,
				analyzerState:      state,
				shouldBuildSummary: args.ShouldBuildSummary(state, function),
			})
		}
	}

	// Start the single function summary building routines
	results := runJobs(jobs, numRoutines, args.IsEntrypoint)
	collectResults(results, &fg, state)

	state.Logger.Infof("Intra-procedural pass done (%.2f s).", time.Since(start).Seconds())

	state.FlowGraph.InsertSummaries(fg)
}

// runJobs runs the intra-procedural analysis on each job in jobs in parallel and returns a slice with all the results.
func runJobs(jobs []singleFunctionJob, numRoutines int,
	isEntrypoint func(*config.Config, ssa.Node) bool) []dataflow.IntraProceduralResult {
	f := func(job singleFunctionJob) dataflow.IntraProceduralResult {
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

// RunCrossFunction runs the inter-procedural analysis pass.
// It builds args.FlowGraph and populates args.DataFlowCandidates based on additional data from the analysis.
func RunCrossFunction(args RunCrossFunctionArgs) {
	args.AnalyzerState.Logger.Infof("Starting inter-procedural pass...")
	start := time.Now()
	args.AnalyzerState.FlowGraph.BuildAndRunVisitor(args.AnalyzerState, args.Visitor, args.IsEntrypoint)
	args.AnalyzerState.Logger.Infof("inter-procedural pass done (%.2f s).", time.Since(start).Seconds())
}

// singleFunctionJob contains all the information necessary to run the intra-procedural analysis on function.
type singleFunctionJob struct {
	analyzerState      *dataflow.AnalyzerState
	function           *ssa.Function
	shouldBuildSummary bool
	postBlockCallback  func(*dataflow.IntraAnalysisState)
	output             chan *dataflow.SummaryGraph
}

// runSingleFunctionJob runs the intra-procedural analysis with the information in job
// and returns the result of the analysis.
func runSingleFunctionJob(job singleFunctionJob,
	isEntrypoint func(*config.Config, ssa.Node) bool) dataflow.IntraProceduralResult {
	job.analyzerState.Logger.Debugf("%-10sPkg: %-60s | Func: %-30s ...",
		"Analyzing", lang.PackageNameFromFunction(job.function), job.function.Name())
	result, err := dataflow.IntraProceduralAnalysis(job.analyzerState, job.function,
		job.shouldBuildSummary, dataflow.GetUniqueFunctionId(), isEntrypoint, job.postBlockCallback)

	if err != nil {
		job.analyzerState.Logger.Errorf("error while analyzing %s:\n\t%v\n", job.function.Name(), err)
		return dataflow.IntraProceduralResult{}
	}

	job.analyzerState.Logger.Debugf("%-10sPkg: %-60s | Func: %-30s | %-5t | %.2f s\n",
		" ", lang.PackageNameFromFunction(job.function), job.function.Name(), job.shouldBuildSummary,
		result.Time.Seconds())

	summary := result.Summary
	if summary != nil {
		summary.ShowAndClearErrors(job.analyzerState.Logger.GetError().Writer())
	}

	return dataflow.IntraProceduralResult{Summary: summary, Time: result.Time}
}

// collectResults waits for the results in c and adds them to graph, candidates. It waits for numProducers
// messages on the done channel to terminate and clean up.
// Operations on graph and candidates are sequential.
// cleans up done and c channels
func collectResults(c []dataflow.IntraProceduralResult, graph *dataflow.InterProceduralFlowGraph,
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

func reportSummaryTime(w io.Writer, result dataflow.IntraProceduralResult) {
	str := fmt.Sprintf("%s, %.2f\n", result.Summary.Parent.String(), result.Time.Seconds())
	w.Write([]byte(str))
}
