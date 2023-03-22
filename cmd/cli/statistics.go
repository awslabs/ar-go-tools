package main

import (
	"go/token"
	"regexp"
	"strings"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/closures"
	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/functional"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// cmdStats prints statistics about the program
// Command is stats [all|general|closures]
func cmdStats(tt *term.Terminal, c *dataflow.Cache, command Command) bool {
	if c == nil {
		writeFmt(tt, "\t- %s%s%s : show stats about program\n", tt.Escape.Blue, cmdStatsName, tt.Escape.Reset)
		writeFmt(tt, "\t  subcommands:\n")
		writeFmt(tt, "\t    help : print help message\n")
		writeFmt(tt, "\t    all : print general and closure stats\n")
		writeFmt(tt, "\t    general  : print general stats about the SSA program\n")
		writeFmt(tt, "\t    closures : print stats about closures with additional options for verbose output:\n")
		writeFmt(tt, "\t        --filter to filter output\n")
		writeFmt(tt, "\t         -U to print unclassified closures locations\n")
		writeFmt(tt, "\t         -C to print anonymous functions capturing channels\n")
		writeFmt(tt, "\t         -I to print closures called immediately after creation\n")

		return false
	}
	if functional.Contains(command.Args, "help") {
		return cmdStats(tt, nil, command)
	}
	all := functional.Contains(command.Args, "all")

	// general ssa stats
	if all || functional.Contains(command.Args, "general") || len(command.Args) == 0 {
		doGeneralStats(tt, c, command)
	}

	// stats about closures
	if all || functional.Contains(command.Args, "closures") {
		doClosureStats(tt, c, command)
	}

	return false
}

func doGeneralStats(tt *term.Terminal, c *dataflow.Cache, _ Command) {
	allFunctions := ssautil.AllFunctions(c.Program)
	result := analysis.SSAStatistics(&allFunctions, []string{})

	WriteSuccess(tt, "SSA stats:")
	writeFmt(tt, " # functions                   %d\n", result.NumberOfFunctions)
	writeFmt(tt, " # nonempty functions          %d\n", result.NumberOfNonemptyFunctions)
	writeFmt(tt, " # blocks                      %d\n", result.NumberOfBlocks)
	writeFmt(tt, " # instructions                %d\n", result.NumberOfInstructions)
}

func doClosureStats(tt *term.Terminal, c *dataflow.Cache, command Command) {
	stats, err := closures.Stats(c)
	if err != nil {
		WriteErr(tt, "could not compute closure statistics.")
	}
	r, _ := regexp.Compile(".*")
	if regexpStr, hasFilter := command.NamedArgs["filter"]; hasFilter {
		r, err = regexp.Compile(regexpStr)
		if err != nil {
			regexErr(tt, regexpStr, err)
		}
	}
	WriteSuccess(tt, "Closures/anonymous function stats:")
	writeFmt(tt, " # MakeClosure                 %d\n", stats.TotalMakeClosures)
	writeFmt(tt, " # Anon functions              %d\n", stats.TotalAnonFunctions)
	writeFmt(tt, " # Anon fun. calls             %d\n", stats.TotalAnonCalls)
	writeFmt(tt, " # Anons capturing channels    %d\n", len(stats.AnonsCapturingChannels))
	writeFmt(tt, " Closure usage:\n")
	writeFmt(tt, "   # Closures w. immediate call  %d\n", len(stats.ClosuresImmediatelyCalled))
	writeFmt(tt, "   # Closures w. local call      %d\n", len(stats.ClosuresCalled))
	writeFmt(tt, "   # Closures returned           %d\n", len(stats.ClosuresReturned))
	writeFmt(tt, "   # Closures passed to call     %d\n", len(stats.ClosuresPassedAsArgs))
	writeFmt(tt, "   # Unclassified                %d\n", len(stats.ClosuresNoClass))

	// Functions capturing channels
	if command.Flags["C"] {
		WriteSuccess(tt, "Anonymous functions capturing channels:")
		var fnames []string
		for function := range stats.AnonsCapturingChannels {
			fnames = append(fnames, function.String())
		}
		slices.Sort(fnames)
		for _, fname := range fnames {
			if r.MatchString(fname) {
				writeFmt(tt, "  %s\n", fname)
			}
		}
	}
	// Closures that are immediately called
	if command.Flags["I"] {
		WriteSuccess(tt, "Closures called immediately at creation:")
		printInstrsWithParent(tt, c, stats.ClosuresImmediatelyCalled, r)
	}

	// Show unclassified closures uses
	if command.Flags["U"] {
		WriteSuccess(tt, "Unclassified closures:")
		printInstrsWithParent(tt, c, stats.ClosuresNoClass, r)
	}
}

func printInstrsWithParent[T any](tt *term.Terminal, c *dataflow.Cache, instrs map[ssa.Instruction]T, target *regexp.Regexp) {
	var fnames []NameAndLoc
	for instruction := range instrs {
		loc := c.Program.Fset.Position(instruction.Parent().Pos())
		if instruction.Pos() != token.NoPos {
			loc = c.Program.Fset.Position(instruction.Pos())
		}
		x := NameAndLoc{
			name: instruction.Parent().String(),
			loc:  loc,
		}
		fnames = append(fnames, x)
	}
	slices.SortFunc(fnames, func(x NameAndLoc, y NameAndLoc) bool { return strings.Compare(x.name, y.name) > 0 })
	for _, x := range fnames {
		if target.MatchString(x.name) {
			writeFmt(tt, "  Parent function %s\n", x.name)
			writeFmt(tt, "         location %s\n", x.loc)
		}
	}
}
