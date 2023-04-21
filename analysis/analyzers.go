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
	"sync"
	"time"

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/ssafuncs"
	"golang.org/x/tools/go/ssa"
)

// SingleFunctionResult represents the result of running a single-function analysis pass.
type SingleFunctionResult struct {
	FlowGraph dataflow.CrossFunctionFlowGraph
}

// RunSingleFunctionArgs represents the arguments for RunSingleFunction.
type RunSingleFunctionArgs struct {
	Cache       *dataflow.Cache
	NumRoutines int

	// ShouldCreateSummary indicates whether a summary object should be created. This does *not* means a summary
	// will be built!
	ShouldCreateSummary func(*ssa.Function) bool

	// ShouldBuildSummary indicates whether the summary should be built when it is created
	ShouldBuildSummary func(*dataflow.Cache, *ssa.Function) bool

	// IsEntrypoint is a function that returns true if the node should be an entrypoint to the analysis.
	// The entrypoint node is treated as a "source" of data.
	IsEntrypoint func(*config.Config, ssa.Node) bool

	// PostBlockCallback will be called each time a block is analyzed if the analysis is running on a single core
	// This is useful for debugging purposes
	PostBlockCallback func(state *dataflow.AnalysisState)
}

// RunSingleFunction runs a single-function analysis pass of program prog in parallel using numRoutines.
// It builds the function summary if shouldBuildSummary evaluates to true.
// isSourceNode and isSinkNode are configure which nodes should be treated as data flow sources/sinks.
func RunSingleFunction(args RunSingleFunctionArgs) SingleFunctionResult {
	logger := args.Cache.Logger
	logger.Println("Starting single-function analysis ...")
	start := time.Now()

	fg := dataflow.NewCrossFunctionFlowGraph(map[*ssa.Function]*dataflow.SummaryGraph{}, args.Cache)
	numRoutines := args.NumRoutines + 1
	if numRoutines < 1 {
		numRoutines = 1
	}

	// Feed the jobs in the jobs channel
	// This pass also ignores some predefined packages
	jobs := make(chan singleFunctionJob, numRoutines)
	go func() {
		defer close(jobs)
		for function := range args.Cache.ReachableFunctions(false, false) {
			if args.ShouldCreateSummary(function) {
				jobs <- singleFunctionJob{
					function:           function,
					cache:              args.Cache,
					shouldBuildSummary: args.ShouldBuildSummary(args.Cache, function),
				}
			}
		}
	}()

	// Start the single function summary building routines
	results := runJobs(jobs, numRoutines, args.IsEntrypoint)
	// Start the collecting routine
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		collectResults(results, &fg, args.Cache)
	}()
	wg.Wait()

	logger.Printf("Single-function pass done (%.2f s).", time.Since(start).Seconds())

	args.Cache.FlowGraph = &fg
	return SingleFunctionResult{FlowGraph: fg}
}

// runJobs runs the single-function analysis on each job in jobs and returns a channel with all the results.
func runJobs(jobs <-chan singleFunctionJob, numRoutines int,
	isEntrypoint func(*config.Config, ssa.Node) bool) <-chan dataflow.SingleFunctionResult {
	results := make(chan dataflow.SingleFunctionResult)
	wg := &sync.WaitGroup{}
	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- runSingleFunctionJob(job, isEntrypoint)
			}
		}()
	}

	// close output once all the goroutines that send to it are done
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// RunCrossFunctionArgs represents the arguments to RunCrossFunction.
type RunCrossFunctionArgs struct {
	Cache        *dataflow.Cache
	Visitor      dataflow.Visitor
	IsEntrypoint func(*config.Config, *ssa.Function) bool
}

// RunCrossFunction runs the cross-function analysis pass.
// It builds args.FlowGraph and populates args.DataFlowCandidates based on additional data from the analysis.
func RunCrossFunction(args RunCrossFunctionArgs) {
	args.Cache.Logger.Println("Starting cross-function pass...")
	start := time.Now()
	args.Cache.FlowGraph.CrossFunctionPass(args.Cache, args.Visitor, args.IsEntrypoint)
	args.Cache.Logger.Printf("Cross-function pass done (%.2f s).", time.Since(start).Seconds())
}

// BuildCrossFunctionGraph builds a full-program (cross-function) analysis cache from program.
func BuildCrossFunctionGraph(cache *dataflow.Cache) (*dataflow.Cache, error) {
	if len(cache.FlowGraph.Summaries) == 0 {
		return nil, fmt.Errorf("cache does not contatain any summaries")
	}

	RunCrossFunction(RunCrossFunctionArgs{
		Cache:        cache,
		Visitor:      dataflow.CrossFunctionGraphVisitor{},
		IsEntrypoint: func(*config.Config, *ssa.Function) bool { return true },
	})

	return cache, nil
}

// singleFunctionJob contains all the information necessary to run the single-function analysis on function.
type singleFunctionJob struct {
	cache              *dataflow.Cache
	function           *ssa.Function
	shouldBuildSummary bool
	postBlockCallback  func(*dataflow.AnalysisState)
	output             chan *dataflow.SummaryGraph
}

// runSingleFunctionJob runs the single-function analysis with the information in job
// and returns the result of the analysis.
func runSingleFunctionJob(job singleFunctionJob,
	isEntrypoint func(*config.Config, ssa.Node) bool) dataflow.SingleFunctionResult {
	result, err := dataflow.SingleFunctionAnalysis(job.cache, job.function,
		job.shouldBuildSummary, dataflow.GetUniqueFunctionId(), isEntrypoint, job.postBlockCallback)
	if err != nil {
		job.cache.Err.Printf("error while analyzing %s:\n\t%v\n", job.function.Name(), err)
		return dataflow.SingleFunctionResult{}
	}
	if job.cache.Config.Verbose {
		job.cache.Logger.Printf("Pkg: %-60s | Func: %-30s | %-5t | %.2f s\n",
			ssafuncs.PackageNameFromFunction(job.function), job.function.Name(), job.shouldBuildSummary,
			result.Time.Seconds())
	}

	summary := result.Summary
	if summary != nil {
		summary.ShowAndClearErrors(job.cache.Logger.Writer())
	}

	return dataflow.SingleFunctionResult{Summary: summary, Time: result.Time}
}

// collectResults waits for the results in c and adds them to graph, candidates. It waits for numProducers
// messages on the done channel to terminate and clean up.
// Operations on graph and candidates are sequential.
// cleans up done and c channels
func collectResults(c <-chan dataflow.SingleFunctionResult, graph *dataflow.CrossFunctionFlowGraph,
	cache *dataflow.Cache) {
	var f *os.File
	var err error
	if cache.Config.ReportSummaries {
		f, err = os.CreateTemp(cache.Config.ReportsDir, "summary-times-*.csv")
		if err != nil {
			cache.Logger.Printf("Could not create summary times report file.")
		}
		defer f.Close()
		cache.Logger.Printf("Saving report of summary times in %s\n", f.Name())
	}

	for result := range c {
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
