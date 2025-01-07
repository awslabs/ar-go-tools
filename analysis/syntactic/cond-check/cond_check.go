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

package cond_check

import (
	"fmt"
	"go/token"
	"slices"
	"strings"
	"sync"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	. "github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// An AnalysisResult of the condition checking analysis returns the list of location where unchecked calls occur.
type AnalysisResult struct {
	UncheckedLocs map[string][]token.Position
}

type AnalysisReqs struct {
	// Tag is the tag to analyze, ignored if non-empty.
	Tag string
}

// Analyze runs the analysis on the program wrapped in the pointer state.
func Analyze(state *ptr.State, reqs AnalysisReqs) (AnalysisResult, error) {
	locs := map[string][]token.Position{}
	for _, spec := range state.Config.SyntacticProblems.CondCheckSpecs {
		if (reqs.Tag == "" || spec.SpecTag() == reqs.Tag) &&
			(Contains(spec.Targets, state.Target) || state.Target == "") {
			specResult, err := AnalyzeSpec(state, spec)
			if err != nil {
				return AnalysisResult{}, fmt.Errorf("while analyzing %s: %s", spec.Tag, err)
			}
			locs[spec.Tag] = specResult
		}
	}
	return AnalysisResult{UncheckedLocs: locs}, nil
}

func AnalyzeSpec(state *ptr.State, spec config.CondCheckSpec) ([]token.Position, error) {
	var locs []token.Position
	for f := range state.ReachableFunctions() {
		hasCallRequiringGuard := false
		lang.IterateInstructions(f, func(index int, i ssa.Instruction) {
			if instrRequiresGuard(state, spec, i) {
				hasCallRequiringGuard = true
			}
		})
		if hasCallRequiringGuard {
			funcResult, err := AnalyzeFunc(state, spec, f)
			if err != nil {
				return []token.Position{}, fmt.Errorf("error analyzing function %s: %s", f, err)
			}
			locs = append(locs, funcResult...)

		}
	}
	return locs, nil
}

func AnalyzeFunc(state *ptr.State, spec config.CondCheckSpec, f *ssa.Function) ([]token.Position, error) {
	state.Logger.Infof("Checking %s which calls a function matching %s", f.Name(), spec.Call.Method)
	var locs []token.Position
	for _, blk := range f.Blocks {
		guardStrs := computeBlockGuards(blk)
		check := sync.OnceValue(func() bool { return checkGuard(spec, guardStrs) })
		for _, instr := range blk.Instrs {
			if instrRequiresGuard(state, spec, instr) {
				state.Logger.Debugf("Check %s", instr)
				if !check() {
					state.Logger.Warnf("Guard not satisfied in call %s", instr)
					state.Logger.Warnf("Guard is: %s", guardToString(guardStrs))
					locs = append(locs, state.Program.Fset.Position(instr.Pos()))
				} else {
					state.Logger.Warnf("Guard satisfied in call %s", instr)
				}
			}
		}
	}

	return locs, nil
}

func guardToString(guards [][]string) string {
	var s []string
	for _, guard := range guards {
		s = append(s, strings.Join(guard, " && "))
	}
	return strings.Join(s, " || ")
}

func checkGuard(spec config.CondCheckSpec, guards [][]string) bool {
	// Each "guard" must be valid
	for _, guard := range guards {
		guardOk := false
		for _, disj := range spec.Requires {
			sat := true
			for _, conj := range disj.Guard {
				if !Contains(guard, conj) {
					sat = false
					continue
				}
			}
			// One of the requires is sat, the guard is valid
			if sat {
				guardOk = true
			}
		}
		if !guardOk {
			return false
		}
	}
	return true
}

// computeBlockGuard computes the sequence of conditions that hold on the block by looking at the dominators.
func computeBlockGuards(block *ssa.BasicBlock) [][]string {
	var cond [][]string
	paths := [][]*ssa.BasicBlock{{block}}
	// Simple algorithm computing all paths and their conditions
	for len(paths) > 0 {
		cur := paths[0]
		paths = paths[1:]
		tail := cur[len(cur)-1]
		if tail.Index == 0 {
			slices.Reverse(cur)
			cond = append(cond, computePathCond(cur))
			continue
		}
		for _, pred := range tail.Preds {
			if !Contains(cur, pred) {
				paths = append(paths, append(cur, pred))
			}
		}
	}
	return cond
}

func computePathCond(blocks []*ssa.BasicBlock) []string {
	var cond []string
	for i := 0; i < len(blocks)-1; i++ {
		maybeCond := blockCond(blocks[i])
		if maybeCond.IsSome() {
			if blocks[i].Succs[0].Index == blocks[i+1].Index {
				cond = append(cond, maybeCond.Value())
			} else {
				cond = append(cond, "!"+maybeCond.Value())
			}
		}
	}
	return cond
}

func instrRequiresGuard(state *ptr.State, spec config.CondCheckSpec, instr ssa.Instruction) bool {
	if instr == nil {
		return false
	}
	call, isCall := instr.(ssa.CallInstruction)
	if !isCall {
		return false
	}
	if _, isBuiltin := call.Common().Value.(*ssa.Builtin); isBuiltin {
		return false
	}
	callees, err := state.ResolveCallee(call)
	if err != nil {
		state.Logger.Errorf("cannot resolve callee %s: %s", call, err)
		return false
	}
	for callee := range callees {
		if spec.Call.MatchPackageAndMethod(callee) {
			return true
		}
	}
	return false
}

func blockCond(block *ssa.BasicBlock) Optional[string] {
	if len(block.Instrs) <= 0 {
		return None[string]()
	}
	ifCond, lastInstrIsIf := block.Instrs[len(block.Instrs)-1].(*ssa.If)
	if !lastInstrIsIf {
		return None[string]()
	}
	return Some(stringCond(ifCond.Cond))
}

func stringCond(v ssa.Value) string {
	switch value := v.(type) {
	case *ssa.Call:
		return value.String()
	case *ssa.Extract:
		return fmt.Sprintf("%s#%d", stringCond(value.Tuple), value.Index)
	case *ssa.BinOp:
		return fmt.Sprintf("%s %s %s", stringCond(value.X), value.Op, stringCond(value.Y))
	case *ssa.UnOp:
		return fmt.Sprintf("%s %s", value.Op, stringCond(value.X))
	case *ssa.Const:
		return value.String()
	default:
		return "<!nae!>"
	}
}
