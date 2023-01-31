// Package analysis contains helper functions for running analysis passes.
package analysis

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/packagescan"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/summaries"
	"golang.org/x/tools/go/ssa"
)

// SingleFunctionResult represents the result of running a single-function analysis pass.
type SingleFunctionResult struct {
	FlowGraph      dataflow.CrossFunctionFlowGraph
	FlowCandidates dataflow.DataFlows
}

// RunSingleFunctionArgs represents the arguments for RunSingleFunction.
type RunSingleFunctionArgs struct {
	Cache              *dataflow.Cache
	NumRoutines        int
	ShouldBuildSummary func(function *ssa.Function) bool
	IsSourceNode       func(*config.Config, ssa.Node) bool
	IsSinkNode         func(*config.Config, ssa.Node) bool
}

// RunSingleFunction runs a single-function analysis pass of program prog in parallel using numRoutines.
// It builds the function summary if shouldBuildSummary evaluates to true.
// isSourceNode and isSinkNode are configure which nodes should be treated as data flow sources/sinks.
func RunSingleFunction(args RunSingleFunctionArgs) SingleFunctionResult {
	logger := args.Cache.Logger
	logger.Println("Starting single-function analysis ...")
	start := time.Now()

	fg := dataflow.NewCrossFunctionFlowGraph(map[*ssa.Function]*dataflow.SummaryGraph{}, args.Cache)

	// flowCandidates contains all the possible data-flow candidates.
	flowCandidates := make(dataflow.DataFlows)

	if args.NumRoutines > 1 {
		// Start the single function summary building routines
		jobs := make(chan singleFunctionJob, args.NumRoutines+1)
		output := make(chan dataflow.SingleFunctionResult, args.NumRoutines+1)
		done := make(chan int)
		for proc := 0; proc < args.NumRoutines; proc++ {
			go jobConsumer(jobs, output, done, args.IsSourceNode, args.IsSinkNode)
		}
		// Start the collecting routine
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			collectResults(output, done, args.NumRoutines, &fg, flowCandidates)
		}()

		// Feed the jobs in the jobs channel
		// This pass also ignores some predefined packages
		for function := range args.Cache.ReachableFunctions(false, false) {
			if args.ShouldBuildSummary(function) {
				jobs <- singleFunctionJob{
					function: function,
					cache:    args.Cache,
				}
			}

		}
		close(jobs)
		wg.Wait()
	} else {
		// Run without goroutines when there is only one routine
		for function := range args.Cache.ReachableFunctions(false, false) {
			if args.ShouldBuildSummary(function) {
				job := singleFunctionJob{
					function: function,
					cache:    args.Cache,
				}
				result := runIntraProceduralOnFunction(job, args.IsSourceNode, args.IsSinkNode)
				if result.Summary != nil {
					fg.Summaries[result.Summary.Parent] = result.Summary
				}
				dataflow.MergeDataFlows(flowCandidates, result.DataFlows)
			}
		}
	}
	logger.Printf("Single-function pass done (%.2f s).", time.Since(start).Seconds())

	return SingleFunctionResult{FlowGraph: fg, FlowCandidates: flowCandidates}
}

// RunCrossFunctionArgs represents the arguments to RunCrossFunction.
type RunCrossFunctionArgs struct {
	Logger             *log.Logger
	Config             *config.Config
	FlowGraph          dataflow.CrossFunctionFlowGraph
	DataFlowCandidates dataflow.DataFlows
	Visitor            dataflow.SourceVisitor
}

// RunCrossFunction runs the cross-function analysis pass.
// It builds args.FlowGraph and populates args.DataFlowCandidates based on additional data from the analysis.
func RunCrossFunction(args RunCrossFunctionArgs) {
	args.Logger.Println("Starting cross-function pass...")
	start := time.Now()
	args.FlowGraph.CrossFunctionPass(args.Config, args.Logger, args.DataFlowCandidates, args.Visitor)
	args.Logger.Printf("Cross-function pass done (%.2f s).", time.Since(start).Seconds())
}

// singleFunctionJob contains all the information necessary to run the single-function analysis on function.
type singleFunctionJob struct {
	cache    *dataflow.Cache
	function *ssa.Function
	output   chan dataflow.SingleFunctionResult
}

// jobConsumer consumes jobs from the jobs channel, and closes output when done.
func jobConsumer(jobs chan singleFunctionJob, output chan dataflow.SingleFunctionResult, done chan int,
	isSourceNode, isSinkNode func(*config.Config, ssa.Node) bool) {
	for job := range jobs {
		output <- runIntraProceduralOnFunction(job, isSourceNode, isSinkNode)
	}
	if done != nil {
		done <- 0
	}
}

// runIntraProceduralOnFunction is a simple function that runs the intraprocedural analysis with the information in job
// and returns the result of the analysis
func runIntraProceduralOnFunction(job singleFunctionJob,
	isSourceNode, isSinkNode func(*config.Config, ssa.Node) bool) dataflow.SingleFunctionResult {
	runAnalysis := !ignoreInFirstPass(job.cache.Config, job.function)
	if job.cache.Config.Verbose {
		job.cache.Logger.Printf("Pkg: %-140s | Func: %s - %t\n",
			packagescan.PackageNameFromFunction(job.function), job.function.Name(), runAnalysis)
	}
	result, err := dataflow.SingleFunctionAnalysis(job.cache, job.function, runAnalysis, isSourceNode, isSinkNode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while analyzing %s:\n\t%v\n", job.function.Name(), err)
	}
	return result
}

// collectResults waits for the results in c and adds them to graph, candidates. It waits for numProducers
// messages on the done channel to terminate and clean up.
// Operations on graph and candidates are sequential.
// cleans up done and c channels
func collectResults(c chan dataflow.SingleFunctionResult, done chan int, numProducers int,
	graph *dataflow.CrossFunctionFlowGraph, candidates dataflow.DataFlows) {
	counter := numProducers
	for {
		select {
		case result := <-c:
			if result.Summary != nil {
				graph.Summaries[result.Summary.Parent] = result.Summary
			}
			dataflow.MergeDataFlows(candidates, result.DataFlows)
		case <-done:
			counter--
			if counter == 0 {
				close(done)
				close(c)
				return
			}
		}
	}
}

// ignoreInFirstPass returns true if the function can be ignored during the first pass of the analysis
// can be used to avoid analyzing functions with many paths.
func ignoreInFirstPass(cfg *config.Config, function *ssa.Function) bool {
	if function == nil {
		return false
	}

	pkg := function.Package()
	if pkg == nil {
		return false
	}

	// Is PkgPrefix specified?
	if cfg != nil && cfg.PkgPrefix != "" {
		pkgKey := pkg.Pkg.Path()
		return !strings.HasPrefix(pkgKey, cfg.PkgPrefix)
	} else {
		// Check package summaries
		return summaries.PkgHasSummaries(pkg)
	}
}
