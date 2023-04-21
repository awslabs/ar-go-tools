// Package analysis contains helper functions for running analysis passes.
package analysis

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/awslabs/argot/analysis/config"
	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/ssafuncs"
	"github.com/awslabs/argot/analysis/summaries"
	"golang.org/x/tools/go/ssa"
)

// SingleFunctionResult represents the result of running a single-function analysis pass.
type SingleFunctionResult struct {
	FlowGraph dataflow.CrossFunctionFlowGraph
}

// RunSingleFunctionArgs represents the arguments for RunSingleFunction.
type RunSingleFunctionArgs struct {
	Cache               *dataflow.Cache
	NumRoutines         int
	ShouldCreateSummary func(function *ssa.Function) bool
	// IsEntrypoint is a function that returns true if the node should be an entrypoint to the analysis.
	// The entrypoint node is treated as a "source" of data.
	IsEntrypoint func(*config.Config, ssa.Node) bool
}

// RunSingleFunction runs a single-function analysis pass of program prog in parallel using numRoutines.
// It builds the function summary if shouldBuildSummary evaluates to true.
// isSourceNode and isSinkNode are configure which nodes should be treated as data flow sources/sinks.
func RunSingleFunction(args RunSingleFunctionArgs) SingleFunctionResult {
	logger := args.Cache.Logger
	logger.Println("Starting single-function analysis ...")
	start := time.Now()

	fg := dataflow.NewCrossFunctionFlowGraph(map[*ssa.Function]*dataflow.SummaryGraph{}, args.Cache)

	if args.NumRoutines > 1 {
		// Start the single function summary building routines
		jobs := make(chan singleFunctionJob, args.NumRoutines+1)
		output := make(chan dataflow.SingleFunctionResult, args.NumRoutines+1)
		done := make(chan int)
		for proc := 0; proc < args.NumRoutines; proc++ {
			go jobConsumer(jobs, output, done, args.IsEntrypoint)
		}
		// Start the collecting routine
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			collectResults(output, done, args.NumRoutines, &fg)
		}()

		// Feed the jobs in the jobs channel
		// This pass also ignores some predefined packages
		for function := range args.Cache.ReachableFunctions(false, false) {
			if args.ShouldCreateSummary(function) {
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
			if args.ShouldCreateSummary(function) {
				job := singleFunctionJob{
					function: function,
					cache:    args.Cache,
				}
				result := runIntraProceduralOnFunction(job, args.IsEntrypoint)
				if result.Summary != nil {
					fg.Summaries[result.Summary.Parent] = result.Summary
				}
			}
		}
	}
	logger.Printf("Single-function pass done (%.2f s).", time.Since(start).Seconds())

	args.Cache.FlowGraph = &fg
	return SingleFunctionResult{FlowGraph: fg}
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
	cache    *dataflow.Cache
	function *ssa.Function
	output   chan dataflow.SingleFunctionResult
}

// jobConsumer consumes jobs from the jobs channel, and closes output when done.
func jobConsumer(jobs chan singleFunctionJob, output chan dataflow.SingleFunctionResult, done chan int,
	isSourceNode func(*config.Config, ssa.Node) bool) {
	for job := range jobs {
		output <- runIntraProceduralOnFunction(job, isSourceNode)
	}
	if done != nil {
		done <- 0
	}
}

// runIntraProceduralOnFunction is a simple function that runs the intraprocedural analysis with the information in job
// and returns the result of the analysis
func runIntraProceduralOnFunction(job singleFunctionJob,
	isSourceNode func(*config.Config, ssa.Node) bool) dataflow.SingleFunctionResult {
	runAnalysis := shouldBuildSummary(job.cache.Config, job.function)
	if job.cache.Config.Verbose {
		job.cache.Logger.Printf("Pkg: %-140s | Func: %s - %t\n",
			ssafuncs.PackageNameFromFunction(job.function), job.function.Name(), runAnalysis)
	}
	result, err := dataflow.SingleFunctionAnalysis(job.cache, job.function,
		runAnalysis, dataflow.GetUniqueFunctionId(), isSourceNode)
	if err != nil {
		job.cache.Err.Printf("error while analyzing %s:\n\t%v\n", job.function.Name(), err)
	}

	if result.Summary != nil {
		result.Summary.ShowAndClearErrors(job.cache.Logger.Writer())
	}

	return result
}

// collectResults waits for the results in c and adds them to graph, candidates. It waits for numProducers
// messages on the done channel to terminate and clean up.
// Operations on graph and candidates are sequential.
// cleans up done and c channels
func collectResults(c chan dataflow.SingleFunctionResult, done chan int, numProducers int,
	graph *dataflow.CrossFunctionFlowGraph) {
	counter := numProducers
	for {
		select {
		case result := <-c:
			if result.Summary != nil {
				graph.Summaries[result.Summary.Parent] = result.Summary
			}
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

// shouldBuildSummary returns true if the function can be ignored during the first pass of the analysis
// can be used to avoid analyzing functions with many paths.
func shouldBuildSummary(cfg *config.Config, function *ssa.Function) bool {
	if function == nil {
		return true
	}

	pkg := function.Package()
	if pkg == nil {
		return true
	}

	// Is PkgPrefix specified?
	if cfg != nil && cfg.PkgPrefix != "" {
		pkgKey := pkg.Pkg.Path()
		return strings.HasPrefix(pkgKey, cfg.PkgPrefix) || pkgKey == "command-line-arguments"
	} else {
		// Check package summaries
		return !summaries.PkgHasSummaries(pkg) || summaries.IsSummaryRequired(function)
	}
}
