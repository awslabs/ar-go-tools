// Package taint contains all the taint analysis functionality in argot. The Analyze function is the main entry
// point of the analysis, and callees the singleFunctionAnalysis and interProcedural analysis functions in two distinct
// whole-program analysis steps.
package taint

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/taint/summaries"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type AnalysisResult struct {
	TaintFlows SinkToSources
	Graph      IFGraph
	Errors     []error
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

	cache := analysis.NewCache(prog, logger, cfg)
	prog.Build()

	// ** First step **
	// - Running the pointer analysis over the whole program. We will query values only in
	// the user defined functions since we plan to analyze only user-defined functions. Any function from the runtime
	// or from the standard library that is called in the program should be summarized in the summaries package.
	// - Running the type analysis to map functions to their type
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go populatePointerCache(cache, wg)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Modifies the implementationsByType and is fine to use concurrently with pointer analysis on cache
		populateTypeCache(cache)
	}()
	wg.Wait()
	if err := cache.CheckError(); err != nil {
		return AnalysisResult{}, err
	}

	// ** Second step **
	// The intra-procedural analysis is run on every function `f` such that `ignoreInFirstPass(f)` is
	// false. A dummy summary is inserted for every function that is not analyzed. If that dummy summary is needed
	// later in the inter-procedural analysis, then we [TODO: what do we do?].
	// The goal of this step is to build function summaries: a graph that represents how data flows through the
	// function being analyzed.

	logger.Println("Starting intra-procedural analysis ...")
	start := time.Now()

	ifg := IFGraph{summaries: map[*ssa.Function]*SummaryGraph{}, cache: cache}

	// taintFlowCandidates contains all the possible taint-flow candidates.
	taintFlowCandidates := make(SinkToSources)
	// Start the single function summary building routines
	jobs := make(chan singleFunctionJob, numRoutines+1)
	output := make(chan SingleFunctionResult, numRoutines+1)
	done := make(chan int)
	for proc := 0; proc < numRoutines; proc++ {
		go jobConsumer(jobs, output, done)
	}
	// Start the collecting routine
	wg.Add(1)
	go collectResults(output, done, numRoutines, &ifg, taintFlowCandidates, wg)

	// Feed the jobs in the jobs channel
	// This pass also ignores some predefined packages
	for function := range ssautil.AllFunctions(prog) {
		// Only build summaries for non-stdlib functions here
		if !summaries.IsStdFunction(function) && userDefinedFunction(function) {
			jobs <- singleFunctionJob{
				function: function,
				cache:    cache,
			}
		}
	}
	close(jobs)
	wg.Wait()
	logger.Printf("Intra-procedural pass done (%.2f s).", time.Since(start).Seconds())

	// ** Third step **
	// the inter-procedural analysis is run over the entire program, which has been summarized in the
	// previous step by building function summaries. This analysis consists in checking whether there exists a sink
	// that is reachable from a source.
	logger.Println("Starting inter-procedural pass...")
	start = time.Now()
	ifg.crossFunctionPass(cfg, logger, taintFlowCandidates)
	logger.Printf("Inter-procedural pass done (%.2f s).", time.Since(start).Seconds())
	return AnalysisResult{TaintFlows: taintFlowCandidates, Graph: ifg}, nil
}

// populateTypeCache is a proxy to run the PopulateTypesToImplementationsMap in a goroutine
func populateTypeCache(c *analysis.Cache) {
	// Load information for analysis and cache it.
	c.Logger.Println("Caching information about types and functions for analysis...")
	start := time.Now()
	c.PopulateTypesToImplementationMap()
	c.Logger.Printf("Cache population terminated, added %d items (%.2f s)\n",
		c.Size(), time.Since(start).Seconds())
}

// populatePointerCache is a proxy to run the pointer analysis in a goroutine
func populatePointerCache(c *analysis.Cache, wg *sync.WaitGroup) {
	defer wg.Done()
	start := time.Now()
	c.Logger.Println("Gathering values and starting pointer analysis...")
	c.PopulatePointerAnalysisResult(userDefinedFunction)
	c.Logger.Printf("Pointer analysis terminated (%.2f s)", time.Since(start).Seconds())
}

// an intraProceduralHob contains all the information necessary to run the intraprocedural analysis on function
type singleFunctionJob struct {
	cache    *analysis.Cache
	function *ssa.Function
	output   chan SingleFunctionResult
}

// jobConsumer consumes jobs from the jobs channel, and closes ouput when done
func jobConsumer(jobs chan singleFunctionJob, output chan SingleFunctionResult, done chan int) {
	for job := range jobs {
		runIntraProceduralOnFunction(job, output)
	}
	if done != nil {
		done <- 0
	}
}

// runIntraProceduralOnFunction is a simple function that runs the intraprocedural analysis with the information in job
func runIntraProceduralOnFunction(job singleFunctionJob, output chan SingleFunctionResult) {
	runAnalysis := !ignoreInFirstPass(job.cache.Config, job.function)
	job.cache.Logger.Printf("Pkg: %-140s | Func: %s - %t\n",
		analysis.PackageNameFromFunction(job.function), job.function.Name(), runAnalysis)
	result, err := singleFunctionAnalysis(job.cache, job.function, runAnalysis)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while analyzing %s:\n\t%v\n", job.function.Name(), err)
	}
	output <- result
}

// collectResults waits for the results in c and adds them to graph, taintFlowCandidates. It waits for numProducers
// messages on the done channel to terminate and clean up.
// Operations on graph and candidates are sequential.
// cleans up done and c channels
func collectResults(c chan SingleFunctionResult, done chan int, numProducers int, graph *IFGraph, candidates SinkToSources,
	wg *sync.WaitGroup) {
	defer wg.Done()
	counter := numProducers
	for {
		select {
		case result := <-c:
			if result.Summary != nil {
				graph.summaries[result.Summary.parent] = result.Summary
			}
			mergeSinkToSources(candidates, result.IntraPaths)
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

// userDefinedFunction returns true when function is a user-defined function. A function is considered
// to be user-defined if it is not in the standard library (in summaries.stdPackages) or in the runtime.
// For example, the functions in the non-standard library packages are considered user-defined.
func userDefinedFunction(function *ssa.Function) bool {
	if function == nil {
		return false
	}
	pkg := function.Package()
	if pkg == nil {
		return false
	}

	// Not in a standard lib package
	return !summaries.IsStdPackage(pkg)
}

// ignoreInFirstPass returns true if the function can be ignored during the first pass of taint analysis
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
