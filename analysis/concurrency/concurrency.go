package concurrency

import (
	"log"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// AnalysisResult contains all the information resulting from the Analyze function
type AnalysisResult struct {
	Cache *dataflow.Cache

	// Ids contains the indices of Go calls. Ids[0] is always nil
	Ids []*ssa.Go

	// GoCalls contains the map from go calls to indices. The indices are >= 1, and such that for some go instruction
	// g, Ids[GoCalls[g]] == g
	GoCalls map[*ssa.Go]uint32

	// NodeColors is a map from callgraph nodes (functions) to a set of go ids. That set should at least contain the
	// index 0 (no go routine) for all reachable nodes, and then any additional id means the function is called inside
	// a goroutine starting at instruction GoCalls[id]
	NodeColors map[*callgraph.Node]map[uint32]bool
}

// Analyze runs all the concurrency specific analyses on the program with the configuration provided.
func Analyze(logger *log.Logger, config *config.Config, program *ssa.Program) (AnalysisResult, error) {

	cache, err := dataflow.BuildFullCache(logger, config, program)
	if err != nil {
		return AnalysisResult{}, err
	}
	return RunAnalysis(cache)
}

// RunAnalysis runs the concurrency analysis on the program contained in the cache.
// The dataflow cache must contain the program, as well as the results from the callgraph analysis and the pointer
// analysis
//
// The analysis currently consists in:
//
// - a first pass to collect all occurrences of `go ...` instructions
//
// - a second pass to mark function with the all the `go ...` instructions they may be called from
func RunAnalysis(cache *dataflow.Cache) (AnalysisResult, error) {
	var callId uint32

	// goCalls maps from a goroutine instruction to a callId
	goCalls := make(map[*ssa.Go]uint32)

	// ids[0] represents the absence of a goroutine on top. For all others i > 0, ids[i] will point to a goroutine
	ids := []*ssa.Go{nil}
	callId = 1
	for function := range cache.ReachableFunctions(false, false) {
		ssafuncs.IterateInstructions(function,
			func(_ int, i ssa.Instruction) {
				if goCall, isGo := i.(*ssa.Go); isGo {
					goCalls[goCall] = callId
					ids = append(ids, goCall)
					callId++
					printGoCallInformation(cache, goCall)
				}
			})
	}

	// Computing a fixpoint on the call graph. A call graph node is put into the queue every time the goroutines
	// it may appear under change.
	cg := cache.PointerAnalysis.CallGraph
	que := []*callgraph.Node{cg.Root}
	vis := map[*callgraph.Node]map[uint32]bool{}
	vis[cg.Root] = map[uint32]bool{0: true}
	for len(que) != 0 {
		elt := que[0]
		que = que[1:]

		for _, e := range elt.Out {
			add := false
			// skip nil edges and edges without Callee
			if e == nil || e.Callee == nil {
				continue
			}

			// when the e.Callee node is visited for the first time, initialize the set of goroutines by
			// setting it to {0}, i.e. the function is executed at least from the main goroutine.
			if vis[e.Callee] == nil {
				add = true
				vis[e.Callee] = map[uint32]bool{}
			}

			// If we have a callsite, then check whether that callsite is a `go ...` instruction. If it is the case,
			// then the callee will be appearing under an additional `go ...` instruction.
			if g, isGo := e.Site.(*ssa.Go); isGo {
				if !vis[e.Callee][goCalls[g]] {
					add = true
					vis[e.Callee][goCalls[g]] = true
				}

			} else {
				// Check that we propagate all ids from caller to callee, and if propagation changes the ids, then
				// we need to enqueue again the callees.
				for id := range vis[elt] {
					if !vis[e.Callee][id] {
						add = true
						vis[e.Callee][id] = true
					}
				}
			}

			if add {
				que = append(que, e.Callee)
			}
		}
	}

	return AnalysisResult{
		Cache:      cache,
		NodeColors: vis,
		GoCalls:    goCalls,
		Ids:        ids,
	}, nil
}

func printGoCallInformation(cache *dataflow.Cache, call *ssa.Go) {
	if call == nil {
		return
	}
	cache.Logger.Printf("Go call: %s", call.String())
	if parent := call.Parent(); parent != nil {
		cache.Logger.Printf("\t%s", parent.Pkg.String())
	}
	cache.Logger.Printf("\t%s", cache.Program.Fset.Position(call.Pos()))
}
