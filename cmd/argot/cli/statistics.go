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

package cli

import (
	"go/token"
	"regexp"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/ssa"
)

// cmdStats prints statistics about the program
// Command is stats [all|general|closures]
func cmdStats(o Outputter, c *Session, command Command, withTest bool) bool {
	if c == nil {
		o.Write("\t- %s%s%s : show stats about program\n", o.EscBlue(), CmdStatsName, o.EscReset())
		o.Write("\t  subcommands:\n")
		o.Write("\t    help : print help message\n")
		o.Write("\t    all : print general and closure stats\n")
		o.Write("\t    general  : print general stats about the SSA program\n")
		o.Write("\t    defers  : print general stats about defers\n")
		o.Write("\t         -A to print functions with more than one defer\n")
		o.Write("\t    closures : print stats about closures with additional options for verbose output:\n")
		o.Write("\t        --filter to filter output\n")
		o.Write("\t         -U to print unclassified closures locations\n")
		o.Write("\t         -C to print anonymous functions capturing channels\n")
		o.Write("\t         -I to print closures called immediately after creation\n")

		return false
	}
	if funcutil.Contains(command.Args, "help") {
		return cmdStats(o, nil, command, withTest)
	}
	all := funcutil.Contains(command.Args, "all")

	if c.lpState == nil {
		o.WriteErr("no program loaded")
		return false
	}

	if all || funcutil.Contains(command.Args, "general") || len(command.Args) == 0 {

		// generate ssa stats with reachable from dataflow analysis
		reachableFunctions, err := c.reachableFunctions()
		if err != nil {
			o.WriteErr("%s", err.Error())
			return false
		}
		doGeneralStats(o, reachableFunctions, command)
	}

	if c.ptrState == nil {
		o.WriteErr("no pointer analysis done, nothing else to report")
		return false
	}
	// general ssa stats
	if all || funcutil.Contains(command.Args, "defers") || len(command.Args) == 0 {
		doDeferStats(o, c.ptrState, command)
	}

	if c.dfState == nil {
		o.WriteErr("no dataflow analysis done, nothing else to report")
		return false
	}
	// stats about closures
	if all || funcutil.Contains(command.Args, "closures") {
		doClosureStats(o, c.dfState, command)
	}

	return false
}

func doGeneralStats(o Outputter, reachableFunctions map[*ssa.Function]bool, _ Command) {
	result := analysis.SSAStatistics(&reachableFunctions, []string{})

	o.WriteSuccess("SSA stats:")
	o.Write(" # functions                   %d\n", result.NumberOfFunctions)
	o.Write(" # nonempty functions          %d\n", result.NumberOfNonemptyFunctions)
	o.Write(" # blocks                      %d\n", result.NumberOfBlocks)
	o.Write(" # instructions                %d\n", result.NumberOfInstructions)
}

func doDeferStats(o Outputter, c *ptr.State, command Command) {
	reachableFunctions := c.ReachableFunctions()
	results := analysis.DeferStats(&reachableFunctions)
	o.Write("%d functions had defers\n", results.NumFunctionsWithDefers)
	o.Write("%d total defers (%f/func)\n", results.NumDefers,
		float32(results.NumDefers)/float32(results.NumFunctionsWithDefers))
	o.Write("%d total `rundefers` (%f/func)\n", results.NumRunDefers,
		float32(results.NumRunDefers)/float32(results.NumFunctionsWithDefers))
	if command.Flags["A"] {
		for name, stat := range results.FunctionsWithManyDefers {
			o.Write("%s has %d defers and %d rundefers\n", name, stat.NumDefers, stat.NumRunDefers)
		}
	}
}

func doClosureStats(o Outputter, c *dataflow.State, command Command) {
	stats, err := analysis.ComputeClosureUsageStats(c)
	if err != nil {
		o.WriteErr("could not compute closure statistics.")
	}
	r, _ := regexp.Compile(".*")
	if regexpStr, hasFilter := command.NamedArgs["filter"]; hasFilter {
		r, err = regexp.Compile(regexpStr)
		if err != nil {
			regexErr(o, regexpStr, err)
		}
	}
	o.WriteSuccess("Closures/anonymous function stats:")
	o.Write(" # MakeClosure                 %d\n", stats.TotalMakeClosures)
	o.Write(" # Anon functions              %d\n", stats.TotalAnonFunctions)
	o.Write(" # Anon fun. calls             %d\n", stats.TotalAnonCalls)
	o.Write(" # Anons capturing channels    %d\n", len(stats.AnonsCapturingChannels))
	o.Write(" Closure usage:\n")
	o.Write("   # Closures w. immediate call  %d\n", len(stats.ClosuresImmediatelyCalled))
	o.Write("   # Closures w. local call      %d\n", len(stats.ClosuresCalled))
	o.Write("   # Closures returned           %d\n", len(stats.ClosuresReturned))
	o.Write("   # Closures passed to call     %d\n", len(stats.ClosuresPassedAsArgs))
	o.Write("   # Unclassified                %d\n", len(stats.ClosuresNoClass))

	// Functions capturing channels
	if command.Flags["C"] {
		o.WriteSuccess("Anonymous functions capturing channels:")
		var fnames []string
		for function := range stats.AnonsCapturingChannels {
			fnames = append(fnames, function.String())
		}
		slices.Sort(fnames)
		for _, fname := range fnames {
			if r.MatchString(fname) {
				o.Write("  %s\n", fname)
			}
		}
	}
	// Closures that are immediately called
	if command.Flags["I"] {
		o.WriteSuccess("Closures called immediately at creation:")
		printInstrsWithParent(o, c.Program, stats.ClosuresImmediatelyCalled, r)
	}

	// Show unclassified closures uses
	if command.Flags["U"] {
		o.WriteSuccess("Unclassified closures:")
		printInstrsWithParent(o, c.Program, stats.ClosuresNoClass, r)
	}
}

func printInstrsWithParent[T any](o Outputter, p *ssa.Program, instrs map[ssa.Instruction]T, target *regexp.Regexp) {
	var fnames []NameAndLoc
	for instruction := range instrs {
		loc := p.Fset.Position(instruction.Parent().Pos())
		if instruction.Pos() != token.NoPos {
			loc = p.Fset.Position(instruction.Pos())
		}
		x := NameAndLoc{
			name: instruction.Parent().String(),
			loc:  loc,
		}
		fnames = append(fnames, x)
	}
	slices.SortFunc(fnames, func(x NameAndLoc, y NameAndLoc) int { return strings.Compare(x.name, y.name) })
	for _, x := range fnames {
		if target.MatchString(x.name) {
			o.Write("  Parent function %s\n", x.name)
			o.Write("         location %s\n", x.loc)
		}
	}
}
