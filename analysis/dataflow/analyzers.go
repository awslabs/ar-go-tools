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

/*
 * Copyright (c)
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package dataflow

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// IntraAnalysisParams represents the arguments for RunIntraProcedural.
type IntraAnalysisParams struct {
	// ShouldBuildSummary indicates whether the summary should be built when it is created
	ShouldBuildSummary func(*State, *ssa.Function) bool

	// ShouldTrack is a function that returns true if the node should be an entrypoint to the analysis.
	// The node may be an entrypoint or an endpoint of an analysis.
	// In particular, ShouldTrack identifies the special nodes that must be tracked but are not callgraph
	// related nodes.
	ShouldTrack func(*State, ssa.Node) bool

	// PostBlockCallback will be called each time a block is analyzed if the analysis is running on a single core
	// This is useful for debugging purposes
	PostBlockCallback func(state *IntraAnalysisState)
}

// RunIntraProceduralPass runs an intra-procedural analysis pass of program prog in parallel using numRoutines, using the
// analyzer state. The args specify the intraprocedural analysis parameters.
// RunIntraProceduralPass updates the summaries stored in the state's FlowGraph
func RunIntraProceduralPass(state *State, numRoutines int, args IntraAnalysisParams) { //argot:ignore df-intra-uses
	state.Logger.Infof("Starting intra-procedural analysis ...")
	start := time.Now()

	fg := NewInterProceduralFlowGraph(map[*ssa.Function]*SummaryGraph{}, state)
	numRoutines = numRoutines + 1
	if numRoutines < 1 {
		numRoutines = 1
	}

	var jobs []singleFunctionJob
	for function := range state.ReachableFunctions() {
		jobs = append(jobs, singleFunctionJob{
			function:      function,
			analyzerState: state,
			// Summary is built only when it is not on-demand, and the summary should be built
			shouldBuildSummary: args.ShouldBuildSummary(state, function),
		})
	}

	// Start the single function summary building routines
	results := runJobs(jobs, numRoutines, args.ShouldTrack)
	collectResults(results, &fg, state)

	state.Logger.Infof("Intra-procedural pass done (%.2f s).", time.Since(start).Seconds())

	state.FlowGraph.InsertSummaries(fg)
}

// runJobs runs the intra-procedural analysis on each job in jobs in parallel and returns a slice with all the results.
func runJobs(jobs []singleFunctionJob, numRoutines int,
	shouldTrack func(*State, ssa.Node) bool) []IntraProceduralResult {
	f := func(job singleFunctionJob) IntraProceduralResult {
		return runSingleFunctionJob(job, shouldTrack)
	}

	return funcutil.MapParallel(jobs, f, numRoutines)
}

// RunInterProcedural runs the inter-procedural analysis pass.
// It builds args.FlowGraph and populates args.DataFlowCandidates based on additional data from the analysis.
func RunInterProcedural(state *State, visitor Visitor, spec ScanningSpec) {
	state.Logger.Infof("Starting inter-procedural pass...")
	start := time.Now()
	state.FlowGraph.BuildAndRunVisitor(state, visitor, spec)
	state.Logger.Infof("inter-procedural pass done (%.2f s).", time.Since(start).Seconds())
}

// singleFunctionJob contains all the information necessary to run the intra-procedural analysis on one function.
type singleFunctionJob struct {
	// analyzerState is the state of the global analyzer. It should only be read, except for specific thread-safe
	// parts. Individual summaries stored in the FlowGraph will not be modified concurrently.
	analyzerState *State

	// function is the function that needs to be summarized
	function *ssa.Function

	// shouldBuildSummary indicates whether the summary will be built. Note that the summary will always be created,
	// but if shouldBuildSummary is false, the intra-procedural dataflow analysis will not be run.
	shouldBuildSummary bool

	// postBlockCallback will be called after every block during the intra-procedural analysis, with the state of
	// the intra-procedural analysis at that point
	postBlockCallback func(*IntraAnalysisState)

	// output is the channel for the summary generated
	output chan *SummaryGraph
}

// runSingleFunctionJob runs the intra-procedural analysis with the information in job
// and returns the result of the analysis.
func runSingleFunctionJob(job singleFunctionJob,
	shouldTrack func(*State, ssa.Node) bool) IntraProceduralResult {
	targetName := formatutil.Sanitize(lang.PackageNameFromFunction(job.function) + "." + job.function.Name())
	job.analyzerState.Logger.Debugf("%-12s %-90s ...", "Summarizing", formatutil.Sanitize(targetName))
	result, err := IntraProceduralAnalysis(job.analyzerState, job.function,
		job.shouldBuildSummary, GetUniqueFunctionID(), shouldTrack, job.postBlockCallback)

	if err != nil {
		job.analyzerState.Logger.Errorf("error while analyzing %q:\n\t%v\n", job.function.Name(), err)
		return IntraProceduralResult{}
	}

	if job.analyzerState.Logger.LogsDebug() {
		if job.shouldBuildSummary {
			job.analyzerState.Logger.Debugf("%-12s %-90s [%.2f s]\n",
				" ", targetName, result.Time.Seconds())
		} else {
			job.analyzerState.Logger.Debugf("%-12s %-90s [ SKIP ]\n", " ", targetName)
		}
	}

	summary := result.Summary
	if summary != nil {
		summary.ShowAndClearErrors(job.analyzerState.Logger.GetError().Writer())
	}

	return IntraProceduralResult{Summary: summary, Time: result.Time}
}

// collectResults waits for the results in c and adds them to graph, candidates. It waits for numProducers
// messages on the done channel to terminate and clean up.
// Operations on graph and candidates are sequential.
// cleans up done and c channels
func collectResults(c []IntraProceduralResult, graph *InterProceduralFlowGraph,
	state *State) {
	var f *os.File
	var err error

	// Check is user required a report of all summaries created
	if state.Config.ReportSummaries {
		f, err = os.CreateTemp(state.Config.ReportsDir, "summary-times-*.csv")
		if err != nil {
			state.Logger.Errorf("Could not create summary times report file.")
		}
		defer f.Close()
		path, err := filepath.Abs(f.Name())
		if err != nil {
			state.Logger.Errorf("Could not find absolute path of summary times report file %q.", f.Name())
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

func reportSummaryTime(w io.Writer, result IntraProceduralResult) {
	str := fmt.Sprintf("%s, %.2f\n",
		formatutil.SanitizeRepr(result.Summary.Parent),
		result.Time.Seconds())
	w.Write([]byte(str))
}
