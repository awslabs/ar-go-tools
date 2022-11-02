package taint

import (
	"fmt"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/taint/summaries"
	"go/types"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log"
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

// Analyze is the main entry point of this package.
func Analyze(logger *log.Logger, cfg *config.Config, prog *ssa.Program) (*TrackingInfo, error) {
	// Collect pointers, build points-to and call-graph
	pCfg := &pointer.Config{
		Mains:           ssautil.MainPackages(prog.AllPackages()),
		Reflection:      false,
		BuildCallGraph:  true,
		Queries:         make(map[ssa.Value]struct{}),
		IndirectQueries: make(map[ssa.Value]struct{}),
	}

	// For each instruction, we'll be adding all possible values.
	fInstr := func(instruction *ssa.Instruction) { addQuery(pCfg, instruction) }

	start := time.Now()
	logger.Println("Gathering values and starting pointer analysis.")

	functions := map[*ssa.Function]bool{}
	for function := range ssafuncs.CollectProgFunctions(prog) {
		if userDefinedFunction(function) {
			functions[function] = true
			ssafuncs.IterateInstructions(function, fInstr)
		}
	}

	// Do the pointer analysis
	ptrRes, err := pointer.Analyze(pCfg)
	if err != nil {
		return nil, fmt.Errorf("pointer analysis: %w", err)
	}

	logger.Printf("Pointer analysis terminated (%.2f s)", time.Since(start).Seconds())
	logger.Printf("Starting intra-procedural analysis on %d functions\n", len(functions))
	start = time.Now()

	tt := &TrackingInfo{
		config:          cfg,
		taintedValues:   make(map[ssa.Value]*Source),
		taintedPointers: make(map[*pointer.PointsToSet]*Source),
		SinkFromSource:  make(map[ssa.Instruction]ssa.Instruction),
	}
	d := 0
	// First pass: intra-procedural
	// This pass also ignores some predefined packages
	for function := range functions {
		if !ignoreInFirstPass(cfg, function) {
			intraProcedural(tt, ptrRes, function)
			d++
		}
	}
	logger.Printf("Intra-procedural pass done (%.2f s).", time.Since(start).Seconds())
	return tt, nil
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
// to be user-defined if it is not in the standard library (in summaries.StdPackages) or in the runtime.
// For example, the functions in the non-standard library packages are considered user-defined.
func userDefinedFunction(function *ssa.Function) bool {
	if function == nil {
		return false
	}
	pkg := function.Package()
	if pkg == nil {
		return false
	}

	_, ok := summaries.StdPackages[pkg.Pkg.Path()]
	// Not in a standard lib package
	if !ok && !strings.HasPrefix(pkg.Pkg.Path(), "runtime") {
		return true
	} else {
		return false
	}
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

	pkgKey := pkg.Pkg.Path()

	// Is PkgPrefix specified?
	if cfg != nil && cfg.PkgPrefix != "" {
		return !strings.HasPrefix(pkgKey, cfg.PkgPrefix)
	} else {
		// Check standard library
		_, ok := summaries.StdPackages[pkgKey]
		if ok {
			return true
		}
		// Check other packages
		_, ok2 := summaries.OtherPackages[pkgKey]
		if ok2 {
			return true
		}
		return false
	}
}
