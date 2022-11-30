// Package taint contains all the taint analysis functionality in argot. The Analyze function is the main entry
// point of the analysis, and callees the intraProcedural and interProcedural analysis functions in two distinct
// whole-program analysis steps.
package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/taint/summaries"
	"go/types"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log"
	"os"
	"strings"
	"time"
)

const PkgLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedExportFile |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes |
	packages.NeedModule

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
	// ** First step **
	// Running the pointer analysis over the whole program. We will query values only in
	// the user defined functions since we plan to analyze only user-defined functions. Any function from the runtime
	// or from the standard library that is called in the program should be summarized in the summaries package.
	start := time.Now()
	logger.Println("Gathering values and starting pointer analysis.")
	pCfg := &pointer.Config{
		Mains:           ssautil.MainPackages(prog.AllPackages()),
		Reflection:      false,
		BuildCallGraph:  true,
		Queries:         make(map[ssa.Value]struct{}),
		IndirectQueries: make(map[ssa.Value]struct{}),
	}

	functions := map[*ssa.Function]bool{}
	for function := range ssautil.AllFunctions(prog) {
		// If the function is a user-defined function (it can be from a dependency) then every value that can
		// can potentially alias is marked for querying.
		if userDefinedFunction(function) {
			functions[function] = true
			ssafuncs.IterateInstructions(function, func(instruction *ssa.Instruction) { addQuery(pCfg, instruction) })
		}
	}

	// Do the pointer analysis
	ptrRes, err := pointer.Analyze(pCfg)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("pointer analysis: %w", err)
	}

	logger.Printf("Pointer analysis terminated (%.2f s)", time.Since(start).Seconds())

	// ** Second step **
	// The intra-procedural analysis is run on every function `f` such that `ignoreInFirstPass(f)` is
	// false. A dummy summary is inserted for every function that is not analyzed. If that dummy summary is needed
	// later in the inter-procedural analysis, then we [TODO: what do we do?].
	// The goal of this step is to build function summaries: a graph that represents how data flows through the
	// function being analyzed.

	logger.Printf("Starting intra-procedural analysis on %d functions\n", len(functions))
	start = time.Now()

	ifg := IFGraph{summaries: map[*ssa.Function]*SummaryGraph{}, callgraph: ptrRes.CallGraph}

	// taintFlowCandidates contains all the possible taint-flow candidates.
	taintFlowCandidates := make(SinkToSources)
	d := 0
	// This pass also ignores some predefined packages
	for function := range functions {
		// Only build summaries for non-stdlib functions here
		if !summaries.IsStdFunction(function) {
			// runAnalysis determines if we just build a placeholder summary or run the analysis
			runAnalysis := !ignoreInFirstPass(cfg, function)
			logger.Printf("Package: %s | function: %s - %t\n",
				analysis.PackageNameFromFunction(function), function.Name(), runAnalysis)
			result, err := intraProcedural(cfg, ptrRes, function, runAnalysis)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while analyzing %s:\n\t%v\n", function.Name(), err)
			}
			if result.Summary != nil {
				ifg.summaries[function] = result.Summary
			}

			mergeSinkToSources(taintFlowCandidates, result.IntraPaths)
			if runAnalysis {
				d++
			}
		}
	}
	logger.Printf("Intra-procedural pass done (%.2f s).", time.Since(start).Seconds())

	// ** Third step **
	// the inter-procedural analysis is run over the entire program, which has been summarized in the
	// previous step by building function summaries. This analysis consists in checking whether there exists a sink
	// that is reachable from a source.
	logger.Println("Starting inter-procedural pass...")
	start = time.Now()
	ifg.interProceduralPass(cfg, logger, taintFlowCandidates)
	logger.Printf("Inter-procedural pass done (%.2f s).", time.Since(start).Seconds())
	return AnalysisResult{TaintFlows: taintFlowCandidates, Graph: ifg}, nil
}

// addQuery adds a query for the instruction to the pointer configuration, performing all the necessary checks to
// ensure the query can be added safely.
func addQuery(cfg *pointer.Config, instruction *ssa.Instruction) {
	if instruction == nil {
		return
	}

	for _, operand := range (*instruction).Operands([]*ssa.Value{}) {
		if *operand != nil && (*operand).Type() != nil {
			typ := (*operand).Type()
			// Add query if value is of a type that can point
			if pointer.CanPoint(typ) {
				cfg.AddQuery(*operand)
			}
			indirectQuery(typ, operand, cfg)
		}
	}
}

// indirectQuery wraps an update to the IndirectQuery of the pointer config. We need to wrap it
// because typ.Underlying() may panic despite typ being non-nil
func indirectQuery(typ types.Type, operand *ssa.Value, cfg *pointer.Config) {
	defer func() {
		if r := recover(); r != nil {
			// Do nothing. Is that panic a bug? Occurs on a *ssa.opaqueType
		}
	}()

	if typ.Underlying() != nil {
		// Add indirect query if value is of pointer type, and underlying type can point
		if ptrType, ok := typ.Underlying().(*types.Pointer); ok {
			if pointer.CanPoint(ptrType.Elem()) {
				cfg.AddIndirectQuery(*operand)
			}
		}
	}
}

// userDefinedFunction returns true when the function argument is a user-defined function. A function is considered
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
