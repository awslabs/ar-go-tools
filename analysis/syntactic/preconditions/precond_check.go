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

package preconditions

import (
	"fmt"
	"go/token"
	"slices"
	"strings"
	"sync"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	fn "github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// An AnalysisResult of the condition checking analysis returns the list of location where unchecked calls occur.
type AnalysisResult struct {
	NumSpecs      int
	UncheckedLocs map[string][]token.Position
}

// AnalysisReqs specifies requirements for the analysis that are not in the config.
type AnalysisReqs struct {
	// Tag is the tag to analyze, ignored if non-empty.
	Tag string
}

// Analyze runs the analysis on the program wrapped in the pointer state.
func Analyze(state *ptr.State, reqs AnalysisReqs) (AnalysisResult, error) {
	locs := map[string][]token.Position{}
	analyzed := 0
	for _, spec := range state.Config.SyntacticProblems.CondCheckSpecs {
		// Check if the spec applies (tag and target)
		if (reqs.Tag == "" || spec.SpecTag() == reqs.Tag) &&
			(fn.Contains(spec.Targets, state.Target) || state.Target == "") {
			analyzed += 1
			state.Logger.Infof("checking tag \"%s\"", formatutil.Bold(spec.Tag))
			specResult, err := analyzeSpec(state, spec)
			if err != nil {
				return AnalysisResult{}, fmt.Errorf("while analyzing %s: %s", spec.Tag, err)
			}
			locs[spec.Tag] = specResult
			state.Report.IncrementSevCount(spec.Severity, len(specResult))
			state.Report.AddEntry(state, config.ReportDesc{
				Tool:     config.SyntacticTool,
				Tag:      spec.Tag,
				Severity: spec.Severity,
				Content:  fn.Map(specResult, func(pos token.Position) string { return pos.String() }),
			})
		}
	}
	return AnalysisResult{NumSpecs: analyzed, UncheckedLocs: locs}, nil
}

// FormattedReport writes res to a string and returns true if the analysis has findings.
func FormattedReport(res AnalysisResult) (string, bool) {
	if res.NumSpecs == 0 {
		return "precondition analysis didn't run; check the tags if you expected a result", false
	}
	w := &strings.Builder{}
	w.WriteString("\nprecondition analysis results:\n")
	w.WriteString("-----------------------------\n")
	if !fn.ExistsInMap(res.UncheckedLocs, func(_ string, locs []token.Position) bool { return len(locs) > 0 }) {
		w.WriteString("all calls have valid preconditions!\n")
		return w.String(), false
	}
	w.WriteString("found some calls that do not have valid preconditions:\n")
	for tag, positions := range res.UncheckedLocs {
		if len(positions) > 0 {
			w.WriteString(fmt.Sprintf("For tag %s:\n", tag))
			for _, position := range positions {
				w.WriteString(fmt.Sprintf("  - %s\n", position))
			}
		} else {
			w.WriteString(fmt.Sprintf("Nothing for tag %s.\n", tag))
		}
	}
	w.WriteString("check the logs for more information")
	return w.String(), true
}

// analyzeSpec analyzes the program in the state with respect to the given precondition checking spec.
func analyzeSpec(state *ptr.State, spec config.CondCheckSpec) ([]token.Position, error) {
	var locs []token.Position
	for f := range state.ReachableFunctions() {
		hasCallRequiringGuard := false
		lang.IterateInstructions(f, func(index int, i ssa.Instruction) {
			if instrRequiresGuard(state, spec, i) {
				hasCallRequiringGuard = true
			}
		})
		if hasCallRequiringGuard {
			funcResult, err := analyzeFunc(state, spec, f)
			if err != nil {
				return []token.Position{}, fmt.Errorf("error analyzing function %s: %s", f, err)
			}
			locs = append(locs, funcResult...)

		}
	}
	return locs, nil
}

type resAndGuards struct {
	res    bool
	guards [][]string
}

func analyzeFunc(state *ptr.State, spec config.CondCheckSpec, f *ssa.Function) ([]token.Position, error) {
	state.Logger.Infof("Checking %s which calls a function matching a call identified in %s",
		f.Name(), spec.Tag)
	var locs []token.Position

	for _, blk := range f.Blocks {
		// Wrap in OnceValue to execute only once, and maybe never if no instruction requires a guard
		check := sync.OnceValue(func() resAndGuards {
			guardStrs := computeBlockGuards(blk)
			res := checkGuard(spec, guardStrs)
			return resAndGuards{res, guardStrs}
		})
		for _, instr := range blk.Instrs {
			if instrRequiresGuard(state, spec, instr) {
				state.Logger.Debugf("Check %s", instr)
				c := check()
				if !c.res {
					state.Logger.Errorf("Preconditions not satisfied in call %s", instr)
					state.Logger.Errorf("Preconditions is: %s", guardToString(c.guards))
					state.Logger.Errorf("Position: %s", state.Program.Fset.Position(instr.Pos()))
					locs = append(locs, state.Program.Fset.Position(instr.Pos()))
				} else {
					state.Logger.Infof("Preconditions satisfied in call %s", instr)
				}
			}
		}
	}

	return locs, nil
}

// guardToString converts a guard (a disjunction of conjunctions of atomic propositions) into a string
// by inserting the && and || operators.
func guardToString(guards [][]string) string {
	var s []string
	for _, guard := range guards {
		s = append(s, strings.Join(guard, " && "))
	}
	return strings.Join(s, " || ")
}

// checkGuard checks that the pathConditions (the conjunctions of propositions, for each control flow path)
// satisfy the requirements in the specification.
func checkGuard(spec config.CondCheckSpec, pathConditions [][]string) bool {
	// Each "guard" must be valid
	for _, pathCondition := range pathConditions {
		guardOk := false
		for _, disj := range spec.Preconditions {
			sat := true
			// pathCondition must contain each conjunct of the guard
			for _, conj := range disj.Precondition {
				if !fn.Contains(pathCondition, conj) {
					sat = false
					break
				}
			}
			// One of the "requires" is sat, the guard is valid and we stop checking
			if sat {
				guardOk = true
				break
			}
		}
		if !guardOk {
			return false
		}
	}
	return true
}

// computeBlockGuard computes the sequence of conditions that hold on the block by looking
// a each control flow path to the block given as argument.
func computeBlockGuards(block *ssa.BasicBlock) [][]string {
	var cond [][]string
	paths := [][]*ssa.BasicBlock{{block}}
	// Naive algorithm computing all paths and their conditions. Only if statements are taken in account.
	// This is sound, but imprecise if the user relied on other conditions.
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
			if !fn.Contains(cur, pred) {
				paths = append(paths, append(cur, pred))
			}
		}
	}
	return cond
}

// computePathCond returns the conjunction of atomic propositions that holds on the specific path of
// blocks. If statements are always the last statement in the block. The branch is deduced by looking
// at which block is next.
func computePathCond(blocks []*ssa.BasicBlock) []string {
	var cond []string
	for i := 0; i < len(blocks)-1; i++ {
		maybeCond := blockCond(blocks[i])
		if maybeCond.IsSome() {
			// Check which branch the next block corresponds to: if 0, the condition is true, otherwise it is false
			// This is by construction of the SSA and branching blocks (note that maybeCond being some value guarantees
			// that the i-th block is a branching block).
			if blocks[i].Succs[0].Index == blocks[i+1].Index {
				cond = append(cond, maybeCond.Value())
			} else {
				cond = append(cond, "!("+maybeCond.Value()+")")
			}
		}
	}
	return cond
}

// instrRequiresGuard is a filter for instructions that require the preconditions, according to the
// specification given as argument.
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
		state.Logger.Warnf("cannot resolve callee %s: %s", call, err)
		return false
	}
	for callee := range callees {
		if fn.Exists(spec.Call, func(c config.CodeIdentifier) bool {
			return c.MatchPackageAndMethodWithCaller(instr.Parent(), callee)
		}) {
			return true
		}
	}
	return false
}

// blockCond optionally returns an atomic proposition for a block given as argument. It only returns
// Some string-represented proposition if and only if the last statement of the block is an If.
func blockCond(block *ssa.BasicBlock) fn.Optional[string] {
	if len(block.Instrs) <= 0 {
		return fn.None[string]()
	}
	ifCond, lastInstrIsIf := block.Instrs[len(block.Instrs)-1].(*ssa.If)
	if !lastInstrIsIf {
		return fn.None[string]()
	}
	return fn.Some(stringCond(ifCond.Cond))
}

// stringCond returns a string representation of the conditional. It attempts to convert the value to an expression
// by recursively looking at its operands. When some operand cannot be converted to a string representation of an
// expression, then it is "<!nae!>" (not an expression).
// Only function call that are not "invokes" are converted, and their arguments are ommitted, e.g. a call to f with
// some arguments is always printed "f(...)". This means the condition-check cannot currently match on specific
// arguments.
//
// TODO: this will be replaced by a proper representation for expressions that can be compared and manipulated.
func stringCond(v ssa.Value) string {
	switch value := v.(type) {
	case *ssa.Call:
		if value.Common().IsInvoke() {
			return value.Common().Method.Name() + "(...)"
		}
		return value.Common().Value.Name() + "(...)"
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
