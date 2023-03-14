package closures

import (
	"fmt"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/astfuncs"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/dataflow"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"golang.org/x/tools/go/ssa"
)

type Statistics struct {
	AnonsCapturingChannels    map[*ssa.Function]bool
	TotalAnonCalls            int
	TotalAnonFunctions        int
	TotalMakeClosures         int
	ClosuresCalled            map[ssa.CallInstruction]ssa.Instruction
	ClosuresImmediatelyCalled map[ssa.Instruction]bool
	ClosuresNoClass           map[ssa.Instruction]bool
	ClosuresPassedAsArgs      map[ssa.CallInstruction]ssa.Instruction
	ClosuresReturned          map[ssa.Instruction]bool
}

func Stats(cache *dataflow.Cache) (Statistics, error) {
	if cache.PointerAnalysis == nil || cache.Program == nil || cache.FlowGraph == nil {
		return Statistics{}, fmt.Errorf("cache should be built to collect stats")
	}
	stats := &Statistics{
		AnonsCapturingChannels:    map[*ssa.Function]bool{},
		ClosuresImmediatelyCalled: map[ssa.Instruction]bool{},
		ClosuresReturned:          map[ssa.Instruction]bool{},
		ClosuresNoClass:           map[ssa.Instruction]bool{},
		ClosuresPassedAsArgs:      map[ssa.CallInstruction]ssa.Instruction{},
		ClosuresCalled:            map[ssa.CallInstruction]ssa.Instruction{},
	}
	for function := range cache.ReachableFunctions(false, false) {
		stats.DoFunction(cache, function)
	}
	return *stats, nil
}

func (s *Statistics) DoFunction(cache *dataflow.Cache, function *ssa.Function) {
	ssafuncs.IterateInstructions(function, func(index int, i ssa.Instruction) {
		if makeClosure, isMakeClosure := i.(*ssa.MakeClosure); isMakeClosure {
			classified := false
			s.TotalMakeClosures += 1
			// Is that closure immediately called in a go, defer or call?
			block := i.Block()
			if block != nil {
				if index+1 < len(block.Instrs) {
					switch i2 := block.Instrs[index+1].(type) {
					case ssa.CallInstruction:
						if i2.Common().Value == i.(ssa.Value) {
							s.ClosuresImmediatelyCalled[i2] = true
							classified = true
						}
					}
				}
			}
			// Is that closure passed as argument to another function call?
			for _, referrer := range *(makeClosure.Referrers()) {
				switch call := referrer.(type) {
				case ssa.CallInstruction:
					// The closure may be passed as an argument to the call
					for _, arg := range call.Common().Args {
						if arg == makeClosure {
							s.ClosuresPassedAsArgs[call] = makeClosure
							classified = true
						}
					}
					// the closure may be called here
					if call.Common().Value == makeClosure {
						s.ClosuresCalled[call] = makeClosure
					}
				case *ssa.Return:
					s.ClosuresReturned[makeClosure] = true
					classified = true
				}
			}
			if !classified {
				s.ClosuresNoClass[makeClosure] = true
			}
		}
	})

	if function.Parent() == nil { // not an anonymous function
		return
	} else {
		s.TotalAnonFunctions += 1
		if node := cache.PointerAnalysis.CallGraph.Nodes[function]; node != nil {
			s.TotalAnonCalls += len(node.In)
		}
	}

	for _, fv := range function.FreeVars {
		if astfuncs.IsChannelEnclosingType(fv.Type()) {
			s.AnonsCapturingChannels[function] = true
		}
	}
	summary := cache.FlowGraph.Summaries[function]
	if summary == nil {
		return
	}
}
